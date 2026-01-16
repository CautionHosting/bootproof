use tracing::debug;

// Nitro-specific
use aws_nitro_enclaves_nsm_api as nsm;
use serde_bytes::ByteBuf;

#[derive(Debug, thiserror::Error)]
pub enum AttestationGenerationError {
    #[error("could not initialize the NSM driver")]
    DriverOpen,

    #[error("an unexpected variant was returned from the NSM device")]
    InvalidVariant,

    #[error("an error {0:?} was returned from the NSM device")]
    ApiError(nsm::api::ErrorCode),
}

pub type Result<T> = std::result::Result<T, AttestationGenerationError>;

// TODO: Move this to an AWS specific module and probably also eventually move it to a
// non-HTTP-stack crate
pub fn generate_attestation(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    debug!("Opening NSM device");
    let nsm_fd = nsm::driver::nsm_init();

    // NOTE: This is a sentinel value in nsm_init. This is also: evil. It literally had the
    // opportunity to return an Err and instead returned a sentinel value.
    if nsm_fd == -1 {
        return Err(AttestationGenerationError::DriverOpen);
    }

    let attestation_request = nsm::api::Request::Attestation {
        user_data: user_data.map(ByteBuf::from),
        nonce: nonce.map(ByteBuf::from),
        public_key: public_key.map(ByteBuf::from),
    };

    debug!("Sending attestation request to NSM device");
    let response = nsm::driver::nsm_process_request(nsm_fd, attestation_request);

    debug!("Closing NSM device");
    nsm::driver::nsm_exit(nsm_fd);

    match response {
        aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => Ok(document),
        aws_nitro_enclaves_nsm_api::api::Response::Error(error_code) => {
            Err(AttestationGenerationError::ApiError(error_code))
        }
        _ => Err(AttestationGenerationError::InvalidVariant),
    }
}
