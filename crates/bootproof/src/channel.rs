//! The lean core: one `Channel` per attestation type on the node, one
//! `Verifier` on the client. Adding a platform later (TDX, GCP, Azure) is
//! one new module implementing these two traits; the Bundle, the HTTP
//! surface, the table renderer, and pinning are untouched.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::wire::{Bundle, Evidence, Fact, Keys};

/// Attest-side: a channel produces signed evidence for a challenge nonce.
pub trait Channel {
    /// Channel name: "tpm2" | "snp" | "aws-cp" | ...
    fn name(&self) -> &'static str;

    /// Is this channel available on this host?
    fn detect(&self) -> bool;

    /// Collect signed evidence bound to `nonce`.
    ///
    /// `nonce` is the 64-byte challenge. The tpm2 channel binds its FRONT 32
    /// bytes as the Quote `qualifyingData` (byte-identical to today's
    /// verifier comparison); the snp channel echoes the FULL 64 bytes into
    /// the report's `report_data` (its front 32 == the client's 32-byte
    /// nonce, which is what `verify/snp.rs` checks). The client's 32-byte
    /// nonce is the front 32 of this challenge.
    ///
    /// `other_docs` are the raw `doc` bytes of the other channels, in
    /// channel-name order: the tpm2 channel folds them into the slot link
    /// (PCR22) before quoting, which is what binds every channel to one TPM
    /// at one moment. Other channels ignore `other_docs`.
    fn collect(&self, nonce: &[u8; 64], other_docs: &[Vec<u8>]) -> Result<Collected, String>;
}

/// What a channel produced for a challenge: its evidence plus any
/// state-bound keys it publishes in the Bundle. Serialized (as one entry of
/// the collect UDS payload) so the `collect` daemon and the `attest` node can
/// hand the exact same value across the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collected {
    pub evidence: Evidence,
    pub keys: Option<Keys>,
}

/// Collect from every channel in the order the slot-link fold requires:
/// the non-tpm2 channels first (best-effort, so an absent channel degrades
/// rather than failing the request), then the tpm2 channel LAST with
/// `other_docs` set to the non-tpm2 channels' raw doc bytes in channel-name
/// order. The tpm2 channel folds those into the slot link (PCR22) before
/// quoting, which is what binds every channel to one TPM at one moment.
///
/// `channels` is the shared registration (built once by `attest::build_channels`
/// and used by both the `collect` daemon and the `attest` in-process fallback).
/// Returns the collected entries in collect order (non-tpm2 channels, then
/// tpm2). The tpm2 channel's failure is propagated: it is the mandatory core.
///
/// This is the SINGLE place the collect ordering + slot-link fold is defined,
/// so the `collect` daemon and the `attest` node can never drift apart.
pub fn collect_all(
    channels: &Arc<Vec<Box<dyn Channel + Send + Sync>>>,
    challenge: &[u8; 64],
) -> Result<Vec<Collected>, String> {
    let mut docs: Vec<Vec<u8>> = Vec::new();
    let mut out: Vec<Collected> = Vec::new();
    for c in channels.iter() {
        if c.name() == "tpm2" {
            continue;
        }
        if !c.detect() {
            warn!(channel = c.name(), "channel inactive (hardware absent); degrading");
            continue;
        }
        match c.collect(challenge, &docs) {
            Ok(col) => {
                docs.push(col.evidence.doc.0.clone());
                out.push(col);
            }
            Err(e) => {
                warn!(channel = c.name(), %e, "channel collect failed; degrading");
            }
        }
    }
    for c in channels.iter() {
        if c.name() != "tpm2" {
            continue;
        }
        let col = c.collect(challenge, &docs)?;
        out.push(col);
    }
    Ok(out)
}

/// Expand the client's 32-byte nonce into the 64-byte challenge the channels
/// bind: the nonce in the front 32 bytes, zero in the back 32.
///
/// This is the SINGLE definition of the challenge contract:
/// - the tpm2 channel binds the FRONT 32 as its Quote `qualifyingData`
///   (byte-identical to today's verifier comparison);
/// - the snp channel echoes the FULL 64 into the report's `report_data`
///   (its front 32 == the client's nonce, which is what `verify/snp.rs`
///   checks).
/// Both the `attest` node (in-process fallback and UDS client) and the
/// `collect` daemon route through this, so the byte contract can't drift.
pub fn challenge_from_nonce(nonce: &[u8; 32]) -> [u8; 64] {
    let mut c = [0u8; 64];
    c[..32].copy_from_slice(nonce);
    c
}

/// The result of a successful channel verification: channel-specific
/// verified data the `facts()` renderer consumes.
pub enum Verified {
    Tpm2(Tpm2Verified),
    Snp(SnpVerified),
}

/// The slot-link (PCR22) check, as an honest 3-state. The node folds the
/// other channels' docs into PCR22 (reset to zero, then extend with
/// H(other docs)) before quoting; the verifier recomputes the expected
/// value from the other evidence and compares. "Absent" is NOT an integrity
/// failure -- a TPM that has no usable resettable slot PCR (AWS NitroTPM
/// only exposes PCRs 0-9; a locality-3-locked PCR22 on a virtual TPM)
/// simply cannot carry the fold, so the node omits it from the quote and
/// the verifier reports the honest hardware boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotLink {
    /// PCR22 == H(0 || H(other docs)): the fold ran and matched. Proven.
    Proven,
    /// PCR22 is in the quote but != H(0 || H(other docs)): the node folded,
    /// the value disagrees. A real integrity failure.
    Mismatched,
    /// PCR22 is not in the quote: the node's TPM has no usable slot PCR, so
    /// the cross-channel fold is not available on this hardware. NotProven.
    NoSlotPcr,
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
    /// The slot-link (PCR22) cross-channel check: Proven, Mismatched, or
    /// NoSlotPcr (the TPM has no usable slot PCR and the fold is unavailable).
    pub slot_link: SlotLink,
    /// EK certificate bytes, if the node bundled one.
    pub ek_cert: Option<Vec<u8>>,
}

/// Verified snp channel data: a SEV-SNP firmware attestation report that
/// decoded, whose VLEK signature and VLEK -> ASVK -> ARK chain verified
/// against the build-pinned roots, whose policy/VMPL met the
/// memory-encryption requirements, and whose report_data echoed the
/// challenge nonce.
#[derive(Debug)]
pub struct SnpVerified {
    /// The raw v5 report bytes (1184).
    pub report_bytes: Vec<u8>,
    /// Guest policy (raw u64), e.g. 0x2030000 (debug-disabled baseline).
    pub policy: u64,
    /// The VMPL the guest runs at (the verifier's required VMPL).
    pub vmpl: u32,
    /// The 64-byte report_data (its front 32 bytes must echo the challenge
    /// nonce; the back 32 are integrity-covered by the VLEK signature).
    pub report_data: [u8; 64],
    /// TSME (total memory encryption) enabled per platform info.
    pub tsme: bool,
    /// The SNP firmware current version string (e.g. "1.58.1").
    pub version: String,
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

    /// A fact this channel OWNS when its evidence is present but FAILED
    /// verification: rendered as NOT PROVEN with the reason. A channel with
    /// no fact it owns returns `None` (the tpm2 channel: every fact it
    /// emits comes from a verified quote). Honest degradation: a present
    /// but failing channel is never silently dropped.
    fn failed_fact(&self, ev: &Evidence, reason: &str) -> Option<Fact> {
        let _ = ev;
        let _ = reason;
        None
    }
}
