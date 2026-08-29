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
    /// Construct with an explicit PCR policy. `pcrs` is the set of expected
    /// PCR values the verifier will require the attestation to match. An empty
    /// set verifies the signature + certificate chain + nonce without any PCR
    /// policy (useful before the PCR state is pinned to known-good values).
    pub fn with_pcr_policy(data: impl Into<Vec<u8>>, pcrs: NitroPcrs) -> Self {
        Self {
            data: data.into(),
            pcrs,
        }
    }

    /// A Nitro Attested COSE value, and the associated PCRs. The PCRs are generated alongside the
    /// EIF and can be used to ensure the Nitro Enclave is running the expected EIF. Additional
    /// PCRs can be added and, if present, will be checked.
    ///
    /// # Errors
    ///
    /// The function may return an error if the 0, 1, or 2 PCRs are not added.
    pub fn new(data: impl Into<Vec<u8>>, pcrs: NitroPcrs) -> Result<Self> {
        for expected_pcr in [0, 1, 2] {
            if !pcrs.contains_key(&expected_pcr) {
                return Err(Error::AttestationParameter(
                    format!("pcr {expected_pcr}").into(),
                ));
            }
        }
        Ok(Self::with_pcr_policy(data, pcrs))
    }
}

impl super::SealedFormat for Nitro {}

const AWS_NITRO_ROOT_CA_DER: &[u8] = include_bytes!("data/nitro-root.der");

/// The embedded (pinned) AWS Nitro Enclaves root CA certificate (DER) that
/// [`Nitro::verify`] chains to.
pub fn aws_nitro_root_ca_der() -> &'static [u8] {
    AWS_NITRO_ROOT_CA_DER
}

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
    let adjusted_time = time_since_epoch.saturating_add(CLOCK_SKEW_TOLERANCE);
    let time = webpki::Time::from_seconds_since_unix_epoch(adjusted_time.as_secs());

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

    if value.first().is_some_and(|v| v & 0x80 != 0) {
        // highest bit set, which would be interpreted as a negative integer
        // encode length as u8 followed by a 0x00
        let len = value.len().checked_add(1).expect("value.len() + 1 overflow");
        let encoded_len = u8::try_from(len).expect("padded value.len() < u8::MAX");
        result.push(encoded_len);
        // push a zero byte so it's unsigned
        result.push(0x00);
        result.extend_from_slice(value);
    } else {
        // highest bit is not set, we can encode once we find the first nonzero byte
        let first_nonzero_index = value.iter().copied().position(|b| b != 0);

        if let Some(start) = first_nonzero_index {
            // we have some acceptable value
            let trimmed = &value[start..];
            let len = u8::try_from(trimmed.len()).expect("value.len() < u8::MAX");
            result.push(len);
            result.extend_from_slice(trimmed);
        } else {
            // it's all zeroes, let's just toss a zero in there
            result.push(1);
            result.push(0);
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

impl VerifiableSignedAttestationFormat for Nitro {
    // Strategy:
    // * Validate provided nonce
    // * Parse payload to get COSE signature and CA info
    // * Verify Nitro certificate against AWS root
    // * Verify COSE signature
    // * Verify PCRs
    // * Verify nonce

    // TODO: Should 

    #[tracing::instrument(skip(self, nonce))]
    fn verify(&self, time_since_epoch: Duration, nonce: &dyn AsNonce) -> Result<Value> {
        debug!("validating provided nonce");
        let nonce = nonce.as_nonce()?;

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
        // The live NitroTPM wire dialect keys the PCR map as "nitrotpm_pcrs";
        // the legacy enclave doc keys it "pcrs". Accept either.
        if let Value::Map(map) = &payload {
            let pcrs = map
                .get(&Value::Text("nitrotpm_pcrs".into()))
                .or_else(|| map.get(&Value::Text("pcrs".into())));
            if let Some(Value::Map(pcrs)) = pcrs {
                for (index, expected_pcr) in &self.pcrs {
                    match pcrs.get(&Value::Integer(i128::from(*index))) {
                        Some(Value::Bytes(validated_pcr)) => {
                            if expected_pcr != validated_pcr {
                                return Err(Error::InvalidAAD(format!("pcr {index}").into()));
                            }
                        }
                        _ => {
                            return Err(Error::MissingData(
                                format!("cose.payload.pcrs[{index}] as bytes").into(),
                            ));
                        }
                    }
                }
            } else if !self.pcrs.is_empty() {
                // A PCR policy is set but the document carries no PCR map.
                return Err(Error::MissingData("cose.payload.pcrs".into()));
            }
        } else if !self.pcrs.is_empty() {
            return Err(Error::MissingData("cose.payload.pcrs".into()));
        }

        debug!("verifying nonce");
        if let Value::Map(map) = &payload && let Some(Value::Bytes(validated_nonce)) = map.get(&Value::Text("nonce".into())) {
            if validated_nonce != nonce {
                return Err(Error::InvalidNonce);
            }
        } else {
            return Err(Error::MissingData("cose.payload.nonce".into()));
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    #[allow(dead_code)]
    fn setup_test_logging() {
        tracing_subscriber::fmt::init();
    }

    // A time shortly after a valid attestation was generated.
    const CBOR_DATA: &'static [u8] = include_bytes!("data/aws-test.cbor");
    const VALID_DURATION: std::time::Duration = std::time::Duration::from_secs(1766510416);
    const NONCE: LazyLock<Vec<u8>> = LazyLock::new(|| {
        hex::decode("d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636").unwrap()
    });

    const PCRS: LazyLock<NitroPcrs> = LazyLock::new(|| {
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

    // A live NSM (NitroTPM) attestation captured from instance i-02a44cb68978c43af,
    // produced by the vendor NSM_REQUEST command and returned in a TPM NV index.
    // Its COSE_Sign1 signature is ECDSA P-384 / SHA-384 over the "Signature1"
    // Sig_structure (coset's context string), signed by the leaf certificate carried
    // in the payload. Unlike the legacy enclave doc (aws-test.cbor), this doc keys its
    // PCRs as "nitrotpm_pcrs" rather than "pcrs", so the full Nitro::verify() PCR step
    // doesn't apply yet (Phase 4); the signature itself is verified here.
    const NSM_LIVE_DATA: &'static [u8] = include_bytes!("data/nsm-live.cbor");

    fn nsm_live_leaf_key() -> Vec<u8> {
        let blob = CoseSign1::from_slice(NSM_LIVE_DATA).unwrap();
        let payload: serde_cbor::Value =
            serde_cbor::from_slice(blob.payload.as_ref().unwrap()).unwrap();
        if let serde_cbor::Value::Map(map) = &payload
            && let Some(serde_cbor::Value::Bytes(certb)) =
                map.get(&serde_cbor::Value::Text("certificate".into()))
        {
            let (_rem, c) = X509Certificate::from_der(certb).unwrap();
            return c.public_key().subject_public_key.data.as_ref().to_vec();
        }
        panic!("no certificate in NSM doc");
    }

    #[test]
    fn nsm_live_doc_signature_valid() {
        let blob = CoseSign1::from_slice(NSM_LIVE_DATA).unwrap();
        let key = nsm_live_leaf_key();
        let tbs = blob.tbs_data(&[]);
        assert!(
            verify_es384(&key, &blob.signature, &tbs).is_ok(),
            "live NSM doc signature must verify"
        );
        // A genuine verifier must reject a mutated message.
        let mut tbs2 = tbs.clone();
        let last = tbs2.len() - 1;
        tbs2[last] ^= 0xFF;
        assert!(
            verify_es384(&key, &blob.signature, &tbs2).is_err(),
            "verifier must reject a mutated tbs"
        );
    }

    /// Full verification (signature + certificate chain to the AWS root + nonce
    /// echo + PCR policy) of a live NitroTPM document. This is the Phase 4 path:
    /// the doc keys its PCRs as `nitrotpm_pcrs`, which `verify` now accepts.
    #[test]
    fn nsm_live_doc_full_verify() {
        let blob = CoseSign1::from_slice(NSM_LIVE_DATA).unwrap();
        let payload: Value =
            serde_cbor::from_slice(blob.payload.as_ref().unwrap()).unwrap();
        let Value::Map(map) = &payload else {
            panic!("payload not a map")
        };
        let pcrs_map = map.get(&Value::Text("nitrotpm_pcrs".into())).unwrap();
        let Value::Map(pcrs) = pcrs_map else {
            panic!("no nitrotpm_pcrs")
        };
        let mut policy: NitroPcrs = HashMap::new();
        for (k, v) in pcrs {
            let Value::Integer(idx) = k else { panic!("non-int pcr index") };
            let Value::Bytes(b) = v else { panic!("non-bytes pcr value") };
            policy.insert(u8::try_from(*idx).expect("pcr index fits u8"), b.clone());
        }
        let Value::Bytes(nonce) = map.get(&Value::Text("nonce".into())).unwrap() else {
            panic!("no nonce")
        };
        let Value::Integer(ts_ms) = map.get(&Value::Text("timestamp".into())).unwrap() else {
            panic!("no timestamp")
        };
        // The leaf cert is only valid for a ~3h window around issuance, so
        // verify at the doc's own timestamp (not wall-clock "now").
        let time = std::time::Duration::from_secs(u64::try_from(*ts_ms).unwrap() / 1000);
        let nonce = nonce.clone();

        // A wrong known-good PCR must be rejected (InvalidAAD).
        let mut bad = policy.clone();

        // With the doc's own PCRs as the known-good policy: full pass.
        Nitro::with_pcr_policy(NSM_LIVE_DATA.to_vec(), policy)
            .verify(time, &nonce)
            .expect("live NSM doc must verify (sig + chain + nonce + PCRs)");

        // With an empty policy: still verifies (sig + chain + nonce, no PCR pin).
        Nitro::with_pcr_policy(NSM_LIVE_DATA.to_vec(), HashMap::new())
            .verify(time, &nonce)
            .expect("empty PCR policy must still verify sig + chain + nonce");

        bad.get_mut(&0).unwrap()[0] ^= 0xFF;
        let r = Nitro::with_pcr_policy(NSM_LIVE_DATA.to_vec(), bad).verify(time, &nonce);
        assert!(matches!(r, Err(Error::InvalidAAD(_))), "wrong PCR must fail");
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
