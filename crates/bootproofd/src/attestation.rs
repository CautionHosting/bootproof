use bootproof::format::{Format, nitro::Nitro};

pub fn generate_attestation(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    // NOTE: In the future, this should have cfg'd blocks for each potential attestation type,
    // chain them all together, and return all successful attestations.
    Nitro.generate(user_data, nonce)
}
