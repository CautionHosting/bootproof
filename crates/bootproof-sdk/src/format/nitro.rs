use super::{Error, Result};
use coset::{CborSerializable, CoseSign1, RegisteredLabelWithPrivate, iana::Algorithm};
use serde_cbor::Value;
use std::time::Duration;
use tracing::{debug, error};
use x509_parser::{certificate::X509Certificate, prelude::FromDer, x509::SubjectPublicKeyInfo};

use super::VerifiableSignedAttestationFormat;

/// A Nitro Enclave inline-signed attestation.
pub struct Nitro(Vec<u8>);

impl Nitro {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self(data.into())
    }
}

impl super::Sealed for Nitro {}

const AWS_NITRO_ROOT_CA_DER: &[u8] = include_bytes!("data/nitro-root.der");

fn value_variant(v: &serde_cbor::Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::Bytes(_items) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_values) => "array",
        Value::Map(_btree_map) => "map",
        Value::Tag(_, _value) => "tag",
        _ => "unknown",
    }
}

fn extract_cert_and_bundle(payload: &Value) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let Value::Map(map) = payload else {
        let variant = value_variant(&payload);
        return Err(Error::MalformedData(
            format!("expected map, got: {variant}").into(),
        ));
    };

    let Some(Value::Bytes(certificate)) = map.get(&Value::Text("certificate".into())) else {
        return Err(Error::MissingData("cose.payload.certificate".into()));
    };

    let Some(Value::Array(cabundle_values)) = map.get(&Value::Text("cabundle".into())) else {
        return Err(Error::MissingData("cose.payload.cabundle".into()));
    };

    let cabundle = cabundle_values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            if let Value::Bytes(cabundle) = value {
                // we must return owned references
                Ok(cabundle.clone())
            } else {
                Err(Error::MalformedData(
                    format!("cose.payload.cabundle[{index}]").into(),
                ))
            }
        })
        .collect::<Result<Vec<_>>>()?;

    Ok((certificate.clone(), cabundle))
}

fn verify_cert_and_bundle_with_root(
    cert: &[u8],
    bundle: &[Vec<u8>],
    root: &[u8],
    time_since_epoch: Duration,
) -> Result<()> {
    let trust_anchor = webpki::TrustAnchor::try_from_cert_der(root).expect("valid const DER cert");
    let end_cert = webpki::EndEntityCert::try_from(cert)
        .map_err(|_| Error::MalformedData("provided cert".into()))?;
    let bundle = bundle.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let time = webpki::Time::from_seconds_since_unix_epoch(time_since_epoch.as_secs());

    if let Err(e) = end_cert.verify_is_valid_tls_server_cert(
        &[&webpki::ECDSA_P384_SHA384],
        &webpki::TlsServerTrustAnchors(&[trust_anchor]),
        &bundle,
        time,
    ) {
        error!("unable to validate tls certificate chain: {e:?}");
        return Err(Error::InvalidCABundle);
    }

    Ok(())
}

// TODO: error handling
fn asn1_encode_int(value: &[u8]) -> Vec<u8> {
    let mut result = vec![0x02];

    if value.get(0).is_some_and(|v| v & 0x80 != 0) {
        // highest bit set, which would be interpreted as a negative integer
        // encode length as u8 followed by a 0x00
        let encoded_len = u8::try_from(value.len() + 1).expect("value.len() < u8::MAX");
        result.push(encoded_len);
        result.push(0x00);
        result.extend_from_slice(value);
    } else {
        // highest bit is not set, we can encode once we find the first nonzero byte
        let first_nonzero_index = value.iter().copied().position(|b| b != 0);

        match first_nonzero_index {
            Some(start) => {
                // we have some acceptable value
                let trimmed = &value[start..];
                let len = u8::try_from(trimmed.len() + 1).expect("value.len() < u8::MAX");
                result.push(len);
                result.extend_from_slice(trimmed);
            }
            None => {
                // it's all zeroes, let's just toss a zero in there
            }
        }
    }

    result
}

// TODO: error handling
fn cose_to_der_es384(sig: [u8; 96]) -> Vec<u8> {
    let r = asn1_encode_int(&sig[..48]);
    let s = asn1_encode_int(&sig[48..]);

    let mut der = vec![0x30];
    let content_len = u8::try_from(r.len().checked_add(s.len()).expect("r + s .len()"))
        .expect("encoded r and s .len() < u8::MAX");
    der.push(content_len);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);

    der
}

#[tracing::instrument(skip(pubkey, sig, data))]
fn verify_es384(pubkey: &[u8], sig: &[u8], data: &[u8]) -> Result<()> {
    debug!("ensuring signature is valid size");
    let sig: [u8; (384 / 8) * 2] = sig
        .try_into()
        .map_err(|_| Error::MalformedData("cose signature; invalid size".into()))?;

    let der_encoded_sig = cose_to_der_es384(sig);

    let algorithm = &ring::signature::ECDSA_P384_SHA384_ASN1;
    let public_key = ring::signature::UnparsedPublicKey::new(algorithm, pubkey);

    debug!("validating provided data with provided siganture");
    public_key.verify(data, &der_encoded_sig).map_err(|e| {
        error!("unable to verify signature: {e}");
        Error::BadSignature
    })
}

impl super::VerifiableSignedAttestationFormat for Nitro {
    // Strategy:
    // * Parse payload to get COSE signature and CA info
    // * Verify Nitro certificate against AWS root
    // * Verify COSE signature

    #[tracing::instrument(skip(self))]
    fn verify(&self, time_since_epoch: Duration) -> Result<serde_cbor::Value> {
        debug!("parsing cose data");
        let cose_signed_blob = CoseSign1::from_slice(&self.0)
            .map_err(|_| Error::MalformedData("cose signed blob".into()))?;

        debug!("parsing payload as cbor value");
        let payload_bytes = cose_signed_blob
            .payload
            .as_ref()
            .ok_or(Error::MalformedData("cose.payload".into()))?;
        let payload: Value = serde_cbor::from_slice(payload_bytes)
            .map_err(|_| Error::MalformedData("cose.payload".into()))?;

        debug!("extracing cert and ca bundle");
        let (cert, cabundle) = extract_cert_and_bundle(&payload)?;
        verify_cert_and_bundle_with_root(
            &cert,
            &cabundle,
            AWS_NITRO_ROOT_CA_DER,
            time_since_epoch,
        )?;

        debug!("parsing x509 certificate");
        let (remainder, cert) = X509Certificate::from_der(&cert).map_err(|_| {
            Error::MalformedData("X509Certificate::from_der(cose.payload.certificate)".into())
        })?;
        if !remainder.is_empty() {
            return Err(Error::MalformedData(
                format!(
                    "{} bytes remain after parsing cose.payload.certificate",
                    remainder.len()
                )
                .into(),
            ));
        }

        let pubkey = cert.public_key();
        let pkey_bytes = pubkey.subject_public_key.data.as_ref();
        let alg = cose_signed_blob
            .protected
            .header
            .alg
            .as_ref()
            .ok_or(Error::MalformedData("cose.protected.header.alg".into()))?;

        cose_signed_blob.verify_signature(&[], |sig, data| match alg {
            RegisteredLabelWithPrivate::Assigned(Algorithm::ES384) => {
                verify_es384(pkey_bytes, sig, data)
            }
            _ => Err(Error::UnsupportedAlgorithm(
                "verify cose".into(),
                format!("{alg:?}").into(),
            )),
        })?;

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn setup_test_logging() {
        tracing_subscriber::fmt::init();
    }

    // A time shortly after a valid attestation was generated.
    const CBOR_DATA: &'static [u8] = include_bytes!("data/aws-test.cbor");
    const VALID_DURATION: std::time::Duration = std::time::Duration::from_secs(1766510416);

    #[test]
    fn it_works() {
        let nitro = Nitro::new(CBOR_DATA);
        nitro.verify(VALID_DURATION).unwrap();
    }

    #[test]
    #[should_panic = "BadSignature"]
    fn mutated_signature_fails() {
        let mut cose_signed_blob = CoseSign1::from_slice(CBOR_DATA).unwrap();
        let cbor_data_2 = cose_signed_blob.clone().to_vec().unwrap();
        assert_eq!(&*CBOR_DATA, &*cbor_data_2);

        // let's mutate the signature field
        cose_signed_blob.signature[2] = !cose_signed_blob.signature[2];
        let cbor_data_3 = cose_signed_blob.to_vec().unwrap();

        let nitro = Nitro::new(cbor_data_3);
        nitro.verify(VALID_DURATION).unwrap();
    }
}
