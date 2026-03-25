#[cfg(feature = "platform-aws")]
pub mod nitro;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub trait Format {
    fn generate(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> Result<Vec<u8>, BoxError>;
}
