use super::{Error, Result, AsNonce};
use coset::{CborSerializable, CoseSign1, RegisteredLabelWithPrivate, iana::Algorithm};
use serde_cbor::Value;
use std::{collections::HashMap, time::Duration};
use tracing::{debug, error};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use super::VerifiableSignedAttestationFormat;

/// A Nitro Enclave inline-signed attestation.
pub struct Nitro {
    data: Vec<u8>,
    pcrs: HashMap<u8, Vec<u8>>,
}

pub type NitroPcrs = HashMap<u8, Vec<u8>>;

impl Nitro {
    /// A Nitro Attested COSE value, and the associated PCRs. The PCRs are generated alongside the
    /// EIF and can be used to ensure the Nitro Enclave is running the expected EIF. Additional
    /// PCRs can be added and, if present, will be checked.
    ///
    /// # Errors
    ///
    /// The function may return an error if the 0, 1, or 2 PCRs are not added.
    pub fn new(data: impl Into<Vec<u8>>, pcrs: NitroPcrs) -> Result<Self> {
        let data = data.into();

        for expected_pcr in [0, 1, 2] {
            if !pcrs.contains_key(&expected_pcr) {
                return Err(Error::AttestationParameter(
                    format!("pcr {expected_pcr}").into(),
                ));
            }
        }

        Ok(Self { data, pcrs })
    }
}

impl super::SealedFormat for Nitro {}

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
        let variant = value_variant(payload);
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

/// XXX/TODO: Clock skew tolerance for certificate validation. Attestation certificates
/// are issued by the enclave's HSM and the client clock may drift slightly.
/// Adding a small forward offset prevents `CertNotValidYet` failures.
const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(60);

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
    let first_nonzero_index = value.iter().copied().position(|b| b != 0);

    if let Some(start) = first_nonzero_index {
        // Raw ES384 signatures use fixed-width unsigned integers. Strip that
        // padding before deciding whether DER needs a sign-protecting zero.
        let trimmed = &value[start..];
        if trimmed.first().is_some_and(|v| v & 0x80 != 0) {
            // highest bit set, which would be interpreted as a negative integer
            // encode length as u8 followed by a 0x00
            let len = trimmed
                .len()
                .checked_add(1)
                .expect("trimmed.len() + 1 overflow");
            let encoded_len = u8::try_from(len).expect("padded trimmed.len() < u8::MAX");
            result.push(encoded_len);
            // push a zero byte so it's unsigned
            result.push(0x00);
        } else {
            let len = u8::try_from(trimmed.len()).expect("trimmed.len() < u8::MAX");
            result.push(len);
        }
        result.extend_from_slice(trimmed);
    } else {
        // it's all zeroes, let's just toss a zero in there
        result.push(1);
        result.push(0);
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

impl VerifiableSignedAttestationFormat for Nitro {
    #[tracing::instrument(skip(self, nonce))]
    fn verify(&self, time_since_epoch: Duration, nonce: &dyn AsNonce) -> Result<Value> {
        self.verify_with_root(
            Some(time_since_epoch.saturating_add(CLOCK_SKEW_TOLERANCE)),
            Some(nonce),
            AWS_NITRO_ROOT_CA_DER,
        )
    }
}

impl Nitro {
    /// Verify a persisted attestation at its signed generation timestamp.
    ///
    /// This proves historical provenance, not freshness. The signed `user_data`
    /// must exactly match `expected_user_data`. Callers must apply their policy
    /// to the authenticated timestamp. Use `verify` with a fresh challenge for
    /// live attestation.
    ///
    /// `Some(nonce)` requires an exact match and the usual minimum nonce length.
    /// `None` requires an absent or null nonce; it does not ignore a present nonce.
    /// Certificate validity is checked without a clock-skew adjustment.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timestamp, certificate chain, signature,
    /// PCRs, nonce, or user data. No payload is returned before all checks succeed.
    #[tracing::instrument(skip_all)]
    pub fn verify_at_attestation_time(
        &self,
        expected_user_data: &[u8],
        expected_nonce: Option<&[u8]>,
    ) -> Result<Value> {
        self.verify_at_attestation_time_with_root(
            expected_user_data,
            expected_nonce,
            AWS_NITRO_ROOT_CA_DER,
        )
    }

    fn verify_at_attestation_time_with_root(
        &self,
        expected_user_data: &[u8],
        expected_nonce: Option<&[u8]>,
        root: &[u8],
    ) -> Result<Value> {
        let expected_nonce = expected_nonce.as_ref().map(|nonce| nonce as &dyn AsNonce);
        let payload = self.verify_with_root(None, expected_nonce, root)?;

        debug!("verifying user data");
        if let Value::Map(map) = &payload
            && let Some(Value::Bytes(user_data)) = map.get(&Value::Text("user_data".into()))
        {
            if user_data != expected_user_data {
                return Err(Error::InvalidAAD("user_data".into()));
            }
        } else {
            return Err(Error::MissingData("cose.payload.user_data".into()));
        }

        Ok(payload)
    }

    // Only production entry points choose the AWS root. Tests use a local root
    // to exercise signed documents that cannot be generated without Nitro.
    fn verify_with_root(
        &self,
        time_since_epoch: Option<Duration>,
        expected_nonce: Option<&dyn AsNonce>,
        root: &[u8],
    ) -> Result<Value> {
        let nonce = expected_nonce.map(AsNonce::as_nonce).transpose()?;

        debug!("parsing cose data");
        let cose_signed_blob = CoseSign1::from_slice(&self.data)
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
        let verification_time = match time_since_epoch {
            Some(time) => time,
            None => attestation_timestamp(&payload)?,
        };
        verify_cert_and_bundle_with_root(&cert, &cabundle, root, verification_time)?;

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

        debug!("verifying COSE signature");
        cose_signed_blob.verify_signature(&[], |sig, data| match alg {
            RegisteredLabelWithPrivate::Assigned(Algorithm::ES384) => {
                verify_es384(pkey_bytes, sig, data)
            }
            _ => Err(Error::UnsupportedAlgorithm(
                "verify cose".into(),
                format!("{alg:?}").into(),
            )),
        })?;

        debug!("verifying local <-> remote PCRs");
        if let Value::Map(map) = &payload
            && let Some(Value::Map(pcrs)) = map.get(&Value::Text("pcrs".into()))
        {
            for (index, expected_pcr) in &self.pcrs {
                if let Some(Value::Bytes(validated_pcr)) =
                    pcrs.get(&Value::Integer(i128::from(*index)))
                {
                    if expected_pcr != validated_pcr {
                        return Err(Error::InvalidAAD(format!("pcr {index}").into()));
                    }
                } else {
                    return Err(Error::MissingData(
                        format!("cose.payload.pcrs[{index}] as bytes").into(),
                    ));
                }
            }
        } else {
            return Err(Error::MissingData("cose.payload.pcrs".into()));
        }

        debug!("verifying nonce");
        let Value::Map(map) = &payload else {
            return Err(Error::MissingData("cose.payload.nonce".into()));
        };
        match (nonce, map.get(&Value::Text("nonce".into()))) {
            (Some(expected), Some(Value::Bytes(actual))) if actual == expected => {}
            (Some(_), Some(Value::Bytes(_))) => return Err(Error::InvalidNonce),
            (Some(_), _) => return Err(Error::MissingData("cose.payload.nonce".into())),
            (None, None | Some(Value::Null)) => {}
            (None, _) => return Err(Error::UnexpectedNonce),
        }

        Ok(payload)
    }
}

fn attestation_timestamp(payload: &Value) -> Result<Duration> {
    let Value::Map(map) = payload else {
        return Err(Error::MissingData("cose.payload.timestamp".into()));
    };
    let Some(timestamp) = map.get(&Value::Text("timestamp".into())) else {
        return Err(Error::MissingData("cose.payload.timestamp".into()));
    };
    let Value::Integer(timestamp) = timestamp else {
        return Err(Error::MalformedData("cose.payload.timestamp".into()));
    };
    let milliseconds = u64::try_from(*timestamp)
        .map_err(|_| Error::MalformedData("cose.payload.timestamp".into()))?;
    Ok(Duration::from_millis(milliseconds))
}

#[cfg(test)]
#[path = "nitro_historical_tests.rs"]
mod historical_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    #[allow(dead_code)]
    fn setup_test_logging() {
        tracing_subscriber::fmt::init();
    }

    // A time shortly after a valid attestation was generated.
    pub(super) const CBOR_DATA: &'static [u8] = include_bytes!("data/aws-test.cbor");
    const VALID_DURATION: std::time::Duration = std::time::Duration::from_secs(1766510416);
    pub(super) static NONCE: LazyLock<Vec<u8>> = LazyLock::new(|| {
        hex::decode("d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636").unwrap()
    });

    pub(super) static PCRS: LazyLock<NitroPcrs> = LazyLock::new(|| {
        let hex0 = hex::decode("ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03").unwrap();
        let hex1 = hex::decode("ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03").unwrap();
        let hex2 = hex::decode("21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a").unwrap();

        HashMap::from_iter([(0, hex0), (1, hex1), (2, hex2)])
    });

    #[test]
    fn it_works() {
        let nitro = Nitro::new(CBOR_DATA, PCRS.clone()).unwrap();
        nitro.verify(VALID_DURATION, &*NONCE).unwrap();
    }

    #[test]
    fn asn1_integer_trims_unsigned_padding_before_sign_check() {
        assert_eq!(asn1_encode_int(&[0x00, 0xd2]), vec![0x02, 0x02, 0x00, 0xd2]);
        assert_eq!(asn1_encode_int(&[0xd2]), vec![0x02, 0x02, 0x00, 0xd2]);
        assert_eq!(asn1_encode_int(&[0x00, 0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(asn1_encode_int(&[0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(asn1_encode_int(&[0x00, 0x00]), vec![0x02, 0x01, 0x00]);
        assert_eq!(asn1_encode_int(&[]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    #[should_panic = "InvalidNonceSize"]
    fn invalid_nonce_size() {
        let nitro = Nitro::new(CBOR_DATA, PCRS.clone()).unwrap();
        nitro.verify(VALID_DURATION, &[0x10; 10]).unwrap();
    }

    #[test]
    #[should_panic = "InvalidNonce"]
    fn invalid_nonce() {
        let nitro = Nitro::new(CBOR_DATA, PCRS.clone()).unwrap();
        nitro.verify(VALID_DURATION, &[0x10; 12]).unwrap();
    }

    #[test]
    #[should_panic = "InvalidAAD"]
    fn invalid_pcrs_fails() {
        let mut pcrs = PCRS.clone();
        let hex0 = pcrs.get_mut(&0).unwrap();
        hex0[1] = !hex0[1];

        let nitro = Nitro::new(CBOR_DATA, pcrs).unwrap();
        nitro.verify(VALID_DURATION, &*NONCE).unwrap();
    }

    #[test]
    #[should_panic = "InvalidAAD"]
    fn invalid_existing_pcrs_fails() {
        let mut pcrs = PCRS.clone();
        pcrs.insert(7, b"abcdefgh".into());

        let nitro = Nitro::new(CBOR_DATA, pcrs).unwrap();
        nitro.verify(VALID_DURATION, &*NONCE).unwrap();
    }

    #[test]
    #[should_panic = "MissingData"]
    fn invalid_additional_pcrs_fails() {
        let mut pcrs = PCRS.clone();
        pcrs.insert(17, b"abcdefgh".into());

        let nitro = Nitro::new(CBOR_DATA, pcrs).unwrap();
        nitro.verify(VALID_DURATION, &*NONCE).unwrap();
    }

    #[test]
    #[should_panic = "InvalidCABundle"]
    fn early_signature_fails() {
        // let's add a day to the expiration
        let duration = VALID_DURATION
            - std::time::Duration::from_secs(
                60 /* seconds */ * 60 /* minutes */ * 24, /* hours */
            );

        let nitro = Nitro::new(CBOR_DATA, PCRS.clone()).unwrap();
        nitro.verify(duration, &*NONCE).unwrap();
    }

    #[test]
    #[should_panic = "InvalidCABundle"]
    fn late_signature_fails() {
        // let's add a day to the expiration
        let duration = VALID_DURATION
            + std::time::Duration::from_secs(
                60 /* seconds */ * 60 /* minutes */ * 24, /* hours */
            );

        let nitro = Nitro::new(CBOR_DATA, PCRS.clone()).unwrap();
        nitro.verify(duration, &*NONCE).unwrap();
    }

    #[test]
    #[should_panic = "InvalidCABundle"]
    fn mutated_certificate_fails() {
        let mut cose_signed_blob = CoseSign1::from_slice(CBOR_DATA).unwrap();
        // let's mutate the CA Bundle. This is extracted from the payload, but is verified before
        // the payload is, so even though we modify the signed payload, the first error encountered
        // is an invalid CA.
        let mut payload: Value =
            serde_cbor::from_slice(&cose_signed_blob.payload.take().unwrap()).unwrap();
        // We mutate the `1` cert; mutating the `0` generates BadSignature but not InvalidCABundle
        // That should be looked into, maybe.
        if let Value::Map(ref mut map) = payload
            && let Some(Value::Array(cabundle)) = map.get_mut(&Value::Text("cabundle".into()))
            && let Some(Value::Bytes(bytes)) = cabundle.get_mut(1)
        {
            bytes[17] = !bytes[17];
        } else {
            panic!("could not get cabundle");
        }
        cose_signed_blob.payload = Some(serde_cbor::to_vec(&payload).unwrap());
        let evil_cbor_data = cose_signed_blob.to_vec().unwrap();

        let nitro = Nitro::new(evil_cbor_data, PCRS.clone()).unwrap();
        nitro.verify(VALID_DURATION, &*NONCE).unwrap();
    }

    #[test]
    #[should_panic = "BadSignature"]
    fn mutated_signature_fails() {
        let mut cose_signed_blob = CoseSign1::from_slice(CBOR_DATA).unwrap();
        // let's mutate the signature field
        cose_signed_blob.signature[2] = !cose_signed_blob.signature[2];
        let evil_cbor_data = cose_signed_blob.to_vec().unwrap();

        let nitro = Nitro::new(evil_cbor_data, PCRS.clone()).unwrap();
        nitro.verify(VALID_DURATION, &*NONCE).unwrap();
    }
}
