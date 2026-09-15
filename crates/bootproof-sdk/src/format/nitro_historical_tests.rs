use super::*;
use coset::{CoseSign1Builder, HeaderBuilder};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair},
};

const TEST_ROOT: &[u8] = include_bytes!("data/historical-test-root.der");
const TEST_LEAF: &[u8] = include_bytes!("data/historical-test-leaf.der");
// Public, test-only signing key. Its certificate is not trusted by either public API.
const TEST_KEY: &[u8] = include_bytes!("data/historical-test-key.pk8");
const NOT_BEFORE: u64 = 1766509560;
const NOT_AFTER: u64 = 1766520363;

fn test_pcrs() -> NitroPcrs {
    HashMap::from([
        (0, vec![0xab; 48]),
        (1, vec![0xab; 48]),
        (2, vec![0xab; 48]),
    ])
}

fn signed_proof(timestamp: Option<Value>, nonce: Option<Value>) -> Vec<u8> {
    let mut payload = std::collections::BTreeMap::from([
        (
            Value::Text("certificate".into()),
            Value::Bytes(TEST_LEAF.to_vec()),
        ),
        (Value::Text("cabundle".into()), Value::Array(vec![])),
        (
            Value::Text("user_data".into()),
            Value::Bytes(b"test certificate bundle hash".to_vec()),
        ),
        (
            Value::Text("pcrs".into()),
            Value::Map(
                test_pcrs()
                    .into_iter()
                    .map(|(index, value)| (Value::Integer(index.into()), Value::Bytes(value)))
                    .collect(),
            ),
        ),
    ]);
    if let Some(value) = timestamp {
        payload.insert(Value::Text("timestamp".into()), value);
    }
    if let Some(value) = nonce {
        payload.insert(Value::Text("nonce".into()), value);
    }
    let random = SystemRandom::new();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, TEST_KEY, &random).unwrap();
    CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(Algorithm::ES384).build())
        .payload(serde_cbor::to_vec(&Value::Map(payload)).unwrap())
        .create_signature(&[], |message| {
            key.sign(&random, message).unwrap().as_ref().to_vec()
        })
        .build()
        .to_vec()
        .unwrap()
}

fn at(seconds: u64) -> Option<Value> {
    Some(Value::Integer(i128::from(seconds) * 1000))
}

#[test]
fn historical_aws_proof_survives_certificate_expiry() {
    let nitro = Nitro::new(tests::CBOR_DATA, tests::PCRS.clone()).unwrap();
    let payload = nitro
        .verify_at_attestation_time(Some(&*tests::NONCE))
        .unwrap();
    assert_eq!(
        attestation_timestamp(&payload).unwrap(),
        Duration::from_millis(1766509563435)
    );
    assert!(matches!(
        nitro.verify(Duration::from_secs(NOT_AFTER + 86400), &*tests::NONCE),
        Err(Error::InvalidCABundle)
    ));
    assert!(matches!(
        nitro.verify_at_attestation_time(None),
        Err(Error::InvalidNonce)
    ));
    assert!(matches!(
        nitro.verify_at_attestation_time(Some(&[0; 10])),
        Err(Error::InvalidNonceSize(10))
    ));
    assert!(matches!(
        nitro.verify_at_attestation_time(Some(&[0; 32])),
        Err(Error::InvalidNonce)
    ));
    let mut wrong_pcrs = tests::PCRS.clone();
    wrong_pcrs.get_mut(&0).unwrap()[0] ^= 1;
    assert!(matches!(
        Nitro::new(tests::CBOR_DATA, wrong_pcrs)
            .unwrap()
            .verify_at_attestation_time(Some(&*tests::NONCE)),
        Err(Error::InvalidAAD(_))
    ));
}

#[test]
fn nonce_less_proofs_require_absent_or_null_nonce_and_a_trusted_signature() {
    for nonce in [None, Some(Value::Null)] {
        let nitro = Nitro::new(signed_proof(at(NOT_BEFORE + 1), nonce), test_pcrs()).unwrap();
        let payload = nitro.verify_with_root(None, None, TEST_ROOT).unwrap();
        assert!(matches!(payload, Value::Map(_)));
        assert!(matches!(
            nitro.verify_at_attestation_time(None),
            Err(Error::InvalidCABundle)
        ));
        assert!(matches!(
            nitro.verify_with_root(None, Some(&[1; 32]), TEST_ROOT),
            Err(Error::MissingData(_))
        ));
    }
    for nonce in [
        Value::Bytes(vec![]),
        Value::Bytes(vec![1; 32]),
        Value::Text("invalid".into()),
    ] {
        let nitro = Nitro::new(signed_proof(at(NOT_BEFORE + 1), Some(nonce)), test_pcrs()).unwrap();
        assert!(matches!(
            nitro.verify_with_root(None, None, TEST_ROOT),
            Err(Error::InvalidNonce)
        ));
    }
    let nitro = Nitro::new(
        signed_proof(at(NOT_BEFORE + 1), Some(Value::Bytes(vec![1; 32]))),
        test_pcrs(),
    )
    .unwrap();
    nitro
        .verify_with_root(None, Some(&[1; 32]), TEST_ROOT)
        .unwrap();
}

#[test]
fn historical_certificate_time_has_no_clock_skew_adjustment() {
    for seconds in [NOT_BEFORE, NOT_AFTER] {
        let nitro = Nitro::new(signed_proof(at(seconds), None), test_pcrs()).unwrap();
        nitro.verify_with_root(None, None, TEST_ROOT).unwrap();
    }
    for seconds in [NOT_BEFORE - 1, NOT_AFTER + 1] {
        let nitro = Nitro::new(signed_proof(at(seconds), None), test_pcrs()).unwrap();
        assert!(matches!(
            nitro.verify_with_root(None, None, TEST_ROOT),
            Err(Error::InvalidCABundle)
        ));
    }
}

#[test]
fn invalid_signed_timestamps_fail_closed() {
    // CBOR cannot encode integers above u64::MAX; check the conversion directly.
    let oversized = Value::Map(std::collections::BTreeMap::from([(
        Value::Text("timestamp".into()),
        Value::Integer(i128::from(u64::MAX) + 1),
    )]));
    assert!(matches!(
        attestation_timestamp(&oversized),
        Err(Error::MalformedData(_))
    ));
    for timestamp in [
        None,
        Some(Value::Null),
        Some(Value::Text("2025".into())),
        Some(Value::Integer(-1)),
    ] {
        let nitro = Nitro::new(signed_proof(timestamp, None), test_pcrs()).unwrap();
        assert!(matches!(
            nitro.verify_with_root(None, None, TEST_ROOT),
            Err(Error::MissingData(_) | Error::MalformedData(_))
        ));
    }
}

#[test]
fn signed_payload_and_signature_mutations_fail_closed() {
    let proof = signed_proof(at(NOT_BEFORE + 1), None);
    for (field, value) in [
        (
            "timestamp",
            Value::Integer(i128::from(NOT_BEFORE + 2) * 1000),
        ),
        (
            "user_data",
            Value::Bytes(b"changed certificate bundle".to_vec()),
        ),
        ("nonce", Value::Bytes(vec![1; 32])),
    ] {
        let mut cose = CoseSign1::from_slice(&proof).unwrap();
        let Value::Map(mut payload) =
            serde_cbor::from_slice(cose.payload.as_ref().unwrap()).unwrap()
        else {
            panic!()
        };
        payload.insert(Value::Text(field.into()), value);
        cose.payload = Some(serde_cbor::to_vec(&Value::Map(payload)).unwrap());
        let nitro = Nitro::new(cose.to_vec().unwrap(), test_pcrs()).unwrap();
        assert!(matches!(
            nitro.verify_with_root(None, None, TEST_ROOT),
            Err(Error::BadSignature)
        ));
    }
    let mut cose = CoseSign1::from_slice(&proof).unwrap();
    cose.signature[0] ^= 1;
    let nitro = Nitro::new(cose.to_vec().unwrap(), test_pcrs()).unwrap();
    assert!(matches!(
        nitro.verify_with_root(None, None, TEST_ROOT),
        Err(Error::BadSignature)
    ));
}
