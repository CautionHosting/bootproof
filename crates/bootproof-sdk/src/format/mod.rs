type ErrorStr = std::borrow::Cow<'static, str>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The attestation parameters are invalid: {0}")]
    AttestationParameter(ErrorStr),

    #[error("The provided data could not be decoded ({0})")]
    MalformedData(ErrorStr),

    #[error("The provided signature was invalid")]
    BadSignature,

    #[error("The data was missing an expected value at: {0}")]
    MissingData(ErrorStr),

    #[error("The provided CA bundle was invalid")]
    InvalidCABundle,

    #[error("An operation ({0}) was requested using an unsupported algorithm: {1}")]
    UnsupportedAlgorithm(ErrorStr, ErrorStr),

    #[error("The expected additional associated data was not successfully matched: {0}")]
    InvalidAAD(ErrorStr),

    #[error("The nonce was too small ({0} bytes < 12) to be considered secure")]
    InvalidNonceSize(usize),

    #[error("The provided nonce did not match the signed nonce")]
    InvalidNonce,
}

type Result<T, E = Error> = std::result::Result<T, E>;

// NOTE: The use of serde_cbor is mostly so we have a should-be-general-purpose "value" to return.
// Once Facet gets CBOR support, we can probably move to facet-value as a format-agnostic
// general-purpose "value".

#[allow(private_bounds)]
pub trait VerifiableSignedAttestationFormat: Sealed {
    fn verify(&self, time_since_epoch: std::time::Duration, nonce: &[u8]) -> Result<serde_cbor::Value>;
}

trait Sealed {}

#[cfg(feature = "nitro")]
pub mod nitro;
