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

    #[error("The signed payload contains a nonce, but none was expected")]
    UnexpectedNonce,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[allow(private_bounds)]
pub trait AsNonce: SealedNonce {
    /// Parse the value as a valid Nonce. This trait is sealed and is not intended to be
    /// implemented for anything other than `AsRef<[u8]>`, as a way of ensuring every format uses
    /// at least minimum-length validation.
    ///
    /// # Errors
    ///
    /// The method may return an error if the nonce is of an invalid length.
    fn as_nonce(&self) -> Result<&[u8]>;
}

trait SealedNonce {}

impl<T> AsNonce for T where T: AsRef<[u8]> + SealedNonce {
    fn as_nonce(&self) -> Result<&[u8]> {
        let len = self.as_ref().len();
        if len < 12 {
            return Err(Error::InvalidNonceSize(len));
        }
        Ok(self.as_ref())
    }
}

impl<T> SealedNonce for T where T: AsRef<[u8]> {}

// NOTE: The use of serde_cbor is mostly so we have a should-be-general-purpose "value" to return.
// Once Facet gets CBOR support, we can probably move to facet-value as a format-agnostic
// general-purpose "value".

#[allow(private_bounds)]
pub trait VerifiableSignedAttestationFormat: SealedFormat {
    /// Verify the provided data, returning the decoded inner contents.
    ///
    /// Note: This function returns a `serde_cbor::Value` as an implementation detail, as there is
    /// no general-purpose, format-agnostic "value". Eventually, a move to facet-value may provide
    /// this type.
    ///
    /// # Errors
    ///
    /// The method may return an error if:
    /// * The provided data could not be properly decoded
    /// * An expected value was not found
    /// * An expected attestation parameter (such as a PCR) was not found, or did not match
    /// * The signature over the provided data was invalid
    /// * The certificate or public key signing the data was not valid
    /// * The nonce was of an invalid size
    /// * The nonce in the signature did not match the provided nonce
    /// * The algorithm used by signing is not supported
    fn verify(&self, time_since_epoch: std::time::Duration, nonce: &dyn AsNonce) -> Result<serde_cbor::Value>;
}

trait SealedFormat {}

#[cfg(feature = "nitro")]
pub mod nitro;
