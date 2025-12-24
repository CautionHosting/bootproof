//! Bootproof Attestation SDK
//!
//! Verify the signature of a bootproof attestation, ensuring the signature is valid and returning
//! a decoded value.

pub mod format;
pub use format::VerifiableSignedAttestationFormat;
