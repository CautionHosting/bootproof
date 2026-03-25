use crate::format::Format;
use aws_nitro_enclaves_nsm_api as nsm;
use serde_bytes::ByteBuf;
use tracing::debug;

pub struct Nitro;

#[derive(Debug, thiserror::Error)]
pub enum NitroAttestationGenerationError {
    #[error("could not initialize the NSM driver")]
    DriverOpen,

    #[error("an unexpected variant was returned from the NSM device")]
    InvalidVariant,

    #[error("an error {0:?} was returned from the NSM device")]
    ApiError(nsm::api::ErrorCode),
}

impl Nitro {
    fn generate_internal(
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, NitroAttestationGenerationError> {
        debug!("Opening NSM device");
        let nsm_fd = nsm::driver::nsm_init();

        // NOTE: This is a sentinel value in nsm_init. This is also: evil. It literally had the
        // opportunity to return an Err and instead returned a sentinel value.
        if nsm_fd == -1 {
            return Err(NitroAttestationGenerationError::DriverOpen);
        }

        let attestation_request = nsm::api::Request::Attestation {
            user_data: user_data.map(ByteBuf::from),
            nonce: nonce.map(ByteBuf::from),
            public_key: None,
        };

        debug!("Sending attestation request to NSM device");
        let response = nsm::driver::nsm_process_request(nsm_fd, attestation_request);

        debug!("Closing NSM device");
        nsm::driver::nsm_exit(nsm_fd);

        match response {
            aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => Ok(document),
            aws_nitro_enclaves_nsm_api::api::Response::Error(error_code) => {
                Err(NitroAttestationGenerationError::ApiError(error_code))
            }
            _ => Err(NitroAttestationGenerationError::InvalidVariant),
        }
    }
}

impl Format for Nitro {
    fn generate(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, crate::format::BoxError> {
        Self::generate_internal(user_data, nonce).map_err(Into::into)
    }
}

#[cfg(test)]
#[test]
fn test_dyn_compatible() {
    let _boxed: Box<dyn Format> = Box::new(Nitro);
}
