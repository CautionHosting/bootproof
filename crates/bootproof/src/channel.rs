//! The lean core: one `Channel` per attestation type on the node, one
//! `Verifier` on the client. Adding a platform later (TDX, GCP, Azure) is
//! one new module implementing these two traits; the Bundle, the HTTP
//! surface, the table renderer, and pinning are untouched.

use crate::wire::{Bundle, Evidence, Fact, Keys};

/// Attest-side: a channel produces signed evidence for a challenge nonce.
pub trait Channel {
    /// Channel name: "tpm2" | "snp" | "aws-cp" | ...
    fn name(&self) -> &'static str;

    /// Is this channel available on this host?
    fn detect(&self) -> bool;

    /// Collect signed evidence bound to `nonce`.
    ///
    /// `other_docs` are the raw `doc` bytes of the other channels, in
    /// channel-name order: the tpm2 channel folds them into the slot link
    /// (PCR22) before quoting, which is what binds every channel to one TPM
    /// at one moment. Other channels ignore `other_docs`.
    fn collect(&self, nonce: &[u8; 32], other_docs: &[Vec<u8>]) -> Result<Collected, String>;
}

/// What a channel produced for a challenge: its evidence plus any
/// state-bound keys it publishes in the Bundle.
pub struct Collected {
    pub evidence: Evidence,
    pub keys: Option<Keys>,
}

/// The result of a successful channel verification: channel-specific
/// verified data the `facts()` renderer consumes.
pub enum Verified {
    Tpm2(Tpm2Verified),
}

/// Verified tpm2 channel data.
pub struct Tpm2Verified {
    /// The attested per-PCR digests (index -> digest), in ascending order,
    /// as covered by the quote.
    pub per_pcr: Vec<(u8, Vec<u8>)>,
    /// The AK public area (raw TPMT_PUBLIC), signature-checked.
    pub ak_public: Vec<u8>,
    /// The state-bound sign key public area (raw TPMT_PUBLIC).
    pub sign_public: Option<Vec<u8>>,
    /// The sign key's authPolicy (the bound PCR policy digest).
    pub sign_policy: Option<Vec<u8>>,
    /// PCR indices the sign key policy binds.
    pub sign_pcrs: Option<Vec<u8>>,
    /// Whether the slot-link (PCR22 == H(other channel docs)) checked out.
    pub slot_link: bool,
    /// EK certificate bytes, if the node bundled one.
    pub ek_cert: Option<Vec<u8>>,
}

/// Verify-side: a channel verifier checks evidence offline.
pub trait Verifier {
    /// Channel name this verifier handles.
    fn name(&self) -> &'static str;

    /// Verify `ev` against `nonce`, with the full `bundle` available so
    /// cross-channel checks (the slot link) can run. Returns the channel's
    /// verified data, or an error explaining what failed.
    fn verify(
        &self,
        ev: &Evidence,
        nonce: &[u8; 32],
        bundle: &Bundle,
    ) -> Result<Verified, String>;

    /// Derive the facts for a verified channel.
    fn facts(&self, v: &Verified) -> Vec<Fact>;
}
