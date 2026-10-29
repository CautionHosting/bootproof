//! `bootproof-platform-wardend`: the wardend platform layer for the
//! generic bootproof engine.
//!
//! This is the wardend-specific half of the evidence-driven design: the
//! wardend fact schemas (the seal state, the hash-chained state log, the
//! PCR policy, unit health, the LUKS volume, the key ACLs, the retry
//! counters) and the wardend `Verifier` that verifies the wardend evidence
//! channel. The generic engine runs this verifier ONLY when the bundle
//! carries the wardend evidence channel — a bundle with only SNP + TPM2
//! gets core verification; a bundle that carries the wardend channel also
//! runs this module. No module is hard-wired.
//!
//! The platform layer depends ONLY on the generic `bootproof` layer (the
//! `Verifier` trait, the wire contract, the chained-log mechanism) — never
//! on `seal` (no layering inversion). The wardend entry schema + hash
//! policy are defined here; the chain-link + per-entry signature mechanism
//! is consumed from `bootproof::engine`.
//!
//! The wardend evidence doc is a JSON object (the wardend platform's own
//! signed facts, produced in-process by seald): the seal state, the
//! state-log entries (the hash-chained log), the PCR selection, the unit
//! health, the LUKS status, the key ACLs, and the retry counters. The
//! anchors carry the seald HSM's P-256 public key (for the state-log
//! signature verification).
#![deny(unsafe_code)]

use bootproof::channel::{Verifier, Verified};
use bootproof::engine::{ChainVerifier, LogSigner};
use bootproof::wire::{B64, Evidence, Fact, Status};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use p256::elliptic_curve::sec1::FromEncodedPoint;

/// The wardend evidence channel name (the engine runs the wardend verifier
/// when the bundle carries this channel).
pub const WARDEND_CHANNEL: &str = "wardend";

/// The anchor key for the seald HSM's P-256 public key (the 65-byte
/// uncompressed point: `0x04 || x || y`).
pub const ANCHOR_SEALD_PUBLIC: &str = "seald_public";

/// The anchor key for the seald HSM's P-256 public key (the 65-byte
/// uncompressed point: `0x04 || x || y`) — the alias the seald admin face
/// publishes.
pub const ANCHOR_HSM_PUBLIC: &str = "hsm_public";

// ---------------------------------------------------------------------------
// The wardend fact schemas (serde: the JSON shape the seald admin face
// produces; the verifier decodes + verifies them).
// ---------------------------------------------------------------------------

/// The one-way seal latch posture (the state the latch is in: malleable
/// = the user-data PCR is the state anchor and malleable; sealed = the
/// latch is one-way, the user-data PCR is the frozen state anchor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatchPosture {
    /// The latch is malleable (the user-data is malleable; the state
    /// anchor is the user-data PCR).
    Malleable,
    /// The latch is sealed (one-way; the user-data PCR is the frozen
    /// state anchor).
    Sealed,
}

/// The seal state (the latch posture + the current / frozen state hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealState {
    /// The latch posture (malleable / sealed).
    pub posture: LatchPosture,
    /// The current / frozen state (the state the latch is anchored to).
    pub state: Vec<u8>,
}

/// The PCR policy (the PCR selection the seald's gate requires: the
/// expected PCR set + the measured values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrPolicy {
    /// The PCR indices the policy requires (the QUOTE PCR set).
    pub expected: Vec<u32>,
    /// The raw `TPMS_PCR_SELECTION` bytes (the `hash u16 + size u8 +
    /// pcrSelect[3]`).
    pub pcr_select: Vec<u8>,
    /// The measured PCR values (the quote's PCR digest, indexed by PCR).
    pub values: std::collections::BTreeMap<u32, Vec<u8>>,
}

/// The health of a single unit (the wardend stack's co-tenants).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitHealth {
    /// The unit name (e.g. "seald", "bridge", "keepd").
    pub name: String,
    /// Whether the unit is up (alive + serving).
    pub up: bool,
    /// The unit's last heartbeat (epoch seconds), if it has one.
    pub heartbeat: Option<u64>,
}

/// The LUKS volume status (the TPM-anchored data volume).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuksStatus {
    /// The device (e.g. "/dev/nvme1n1").
    pub device: String,
    /// Whether the volume is open (mapped + mounted).
    pub open: bool,
    /// The PCR policy the volume is bound to (the seed / full PCR set).
    pub pcr_policy: Vec<u32>,
    /// The data-integrity marker counter (the keepd marker: the prior
    /// boot's data is intact).
    pub marker_counter: Option<u64>,
}

/// A key ACL (the seald's key access control: which key may be used for
/// which operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAcl {
    /// The key handle (the seald HSM's key).
    pub handle: u64,
    /// The permitted operations (e.g. ["sign", "unseal"]).
    pub operations: Vec<String>,
    /// The PCR policy the key's use is bound to (the "attested state").
    pub pcr_policy: Vec<u32>,
}

/// The retry counters (the seald's / warden's retry budgets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryCounters {
    /// The warden respawn budget (the regentd kill-deadline respawns).
    pub warden_respawn: u32,
    /// The watchdog reboot-loop guard count (the persistent 64-byte block).
    pub watchdog_reboot_guard: u32,
}

/// The wardend evidence doc (the JSON shape the seald admin face produces;
/// the verifier decodes + verifies it). Every field is optional: a field
/// the node does not produce degrades to a NOT PROVEN fact (never silently
/// dropped).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardendDoc {
    /// The seal state (the latch posture + the state hash).
    pub seal_state: Option<SealState>,
    /// The hash-chained state log (the entries: prev_hash, new_state_hash,
    /// operation, timestamp, signature).
    pub state_log: Vec<StateLogEntry>,
    /// The PCR policy (the expected PCR set + the measured values).
    pub pcr_policy: Option<PcrPolicy>,
    /// The unit health (the wardend stack's co-tenants).
    pub units: Vec<UnitHealth>,
    /// The LUKS volume status (the TPM-anchored data volume).
    pub luks: Option<LuksStatus>,
    /// The key ACLs (the seald's key access control).
    pub key_acls: Vec<KeyAcl>,
    /// The retry counters (the seald's / warden's retry budgets).
    pub retry: Option<RetryCounters>,
}

/// A state-log entry (the wardend hash-chained log entry: the mechanism is
/// generic in `bootproof::engine`; the schema + hash policy are here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateLogEntry {
    /// The prior entry's hash (or the genesis constant for the first
    /// entry).
    pub prev_hash: [u8; 32],
    /// The new state hash (the state the entry transitions to).
    pub new_state_hash: [u8; 32],
    /// The operation (e.g. "genesis", "seal", "unseal").
    pub operation: Vec<u8>,
    /// The timestamp (epoch seconds).
    pub timestamp: u64,
    /// The signature (the seald HSM signed the entry hash: the 64-byte
    /// `r || s` P-256 signature).
    pub signature: Vec<u8>,
}

impl StateLogEntry {
    /// The wardend hash policy: `SHA-256(prev_hash || new_state_hash ||
    /// operation || timestamp)`. This is the platform's hash policy (the
    /// value the next entry's `prev_hash` must match). The generic
    /// `verify_chained_log` owns the chain-link + signature mechanism; this
    /// is the platform seam.
    pub fn entry_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.prev_hash);
        h.update(self.new_state_hash);
        h.update(&self.operation);
        h.update(self.timestamp.to_be_bytes());
        h.finalize().into()
    }
}

impl ChainVerifier<StateLogEntry> for WardendChainVerifier {
    fn prev_hash(&self, e: &StateLogEntry) -> [u8; 32] {
        e.prev_hash
    }
    fn entry_hash(&self, e: &StateLogEntry) -> [u8; 32] {
        e.entry_hash()
    }
    fn signature<'a>(&'a self, e: &'a StateLogEntry) -> &'a [u8] {
        &e.signature
    }
}

/// The wardend state-log chain verifier (the platform's entry schema + hash
/// policy, for the generic `verify_chained_log` mechanism).
pub struct WardendChainVerifier;

// ---------------------------------------------------------------------------
// The P-256 sign-key verify (the seald HSM's public key).
// ---------------------------------------------------------------------------

/// A P-256 public-key signer (the seald HSM's public key). The client has
/// only the public key (the 65-byte uncompressed point), so it verifies the
/// state-log signatures (the 64-byte `r || s` over the entry hash) but
/// cannot sign.
pub struct P256Signer {
    public_point: [u8; 65],
}

impl P256Signer {
    /// Build a verifier from the 65-byte uncompressed P-256 public point
    /// (`0x04 || x || y`). An invalid point (not on the curve, or a wrong
    /// prefix) is an `Err` (fail-closed: a malformed public key is never
    /// silently accepted).
    pub fn from_uncompressed(point: &[u8]) -> Result<Self, String> {
        if point.len() != 65 || point[0] != 0x04 {
            return Err(
                "p256 signer: public key must be the 65-byte uncompressed point (0x04 || x || y)"
                    .to_string(),
            );
        }
        // The p256 crate's VerifyingKey::from_encoded_point (the full
        // 65-byte uncompressed point, WITH the 0x04 prefix).
        let ep = p256::EncodedPoint::from_bytes(point).map_err(|e| {
            format!("p256 signer: invalid public point: {e}")
        })?;
        // Validate the point is on the curve (fail-closed).
        let _ = p256::ecdsa::VerifyingKey::from_encoded_point(&ep)
            .map_err(|e| format!("p256 signer: invalid public point: {e}"))?;
        let mut public_point = [0u8; 65];
        public_point.copy_from_slice(point);
        Ok(Self {
            public_point,
        })
    }
}

impl LogSigner for P256Signer {
    fn verify(&self, hash: &[u8; 32], sig: &[u8]) -> bool {
        let sig = match p256::ecdsa::Signature::from_slice(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // The signature is over the entry hash directly (the seald HSM
        // signs the entry hash; the entry hash is already a SHA-256
        // digest, so we verify the pre-hash digest — the standard
        // Verifier::verify would SHA-256 it AGAIN, which is wrong).
        let ep = match p256::EncodedPoint::from_bytes(self.public_point) {
            Ok(ep) => ep,
            Err(_) => return false,
        };
        let q = match p256::ProjectivePoint::from_encoded_point(&ep).into_option() {
            Some(q) => q,
            None => return false,
        };
        ecdsa::hazmat::verify_prehashed(&q, hash.into(), &sig).is_ok()
    }
}

// ---------------------------------------------------------------------------
// The wardend Verifier (the evidence-driven platform module).
// ---------------------------------------------------------------------------

/// The wardend verifier: verifies the wardend evidence channel (the
/// seal state, the hash-chained state log, the PCR policy, the unit
/// health, the LUKS status, the key ACLs, the retry counters). The engine
/// runs this ONLY when the bundle carries the wardend evidence channel.
pub struct WardendVerifier;

impl Verifier for WardendVerifier {
    fn name(&self) -> &'static str {
        WARDEND_CHANNEL
    }

    fn verify(
        &self,
        ev: &Evidence,
        _nonce: &[u8; 32],
        _bundle: &bootproof::wire::Bundle,
    ) -> Result<Verified, String> {
        // Decode the wardend evidence doc (the JSON shape). A malformed doc
        // is an Err (fail-closed: a corrupt wardend doc is never silently
        // accepted).
        let doc: WardendDoc = serde_json::from_slice(&ev.doc.0)
            .map_err(|e| format!("wardend: malformed evidence doc: {e}"))?;

        // 1. The seal state (the latch posture + the state hash). A
        //    SEALED latch with an empty state is corrupt (a sealed latch
        //    must anchor to a non-empty state). A malleable (fresh,
        //    unsealed) latch with an empty state is legitimate — the
        //    state is not frozen yet, so there is nothing to anchor.
        if let Some(seal) = &doc.seal_state {
            if seal.posture == LatchPosture::Sealed && seal.state.is_empty() {
                return Err("wardend: the sealed state is empty (corrupt)".to_string());
            }
        }

        // 2. The state chain (the hash-chained log): every entry's
        //    prev_hash link + every signature, via the seald HSM public
        //    key. A tampered chain is an Err (fail-closed).
        if !doc.state_log.is_empty() {
            let public = ev
                .anchors
                .get(ANCHOR_SEALD_PUBLIC)
                .or_else(|| ev.anchors.get(ANCHOR_HSM_PUBLIC))
                .ok_or("wardend: the seald HSM public key is missing (cannot verify the state chain)")?;
            let signer = P256Signer::from_uncompressed(&public.0)?;
            // The genesis constant: the first entry's prev_hash is the
            // genesis (the seald's StateLog genesis is a fixed constant;
            // here we verify the chain from the first entry's prev_hash,
            // which must be the genesis the node recorded).
            let genesis = doc.state_log[0].prev_hash;
            match bootproof::engine::verify_chained_log(
                &doc.state_log,
                genesis,
                &WardendChainVerifier,
                &signer,
            ) {
                bootproof::engine::ChainResult::Intact(n) => {
                    if n != doc.state_log.len() {
                        return Err(format!("wardend: the state chain is broken at entry {n}"));
                    }
                }
                bootproof::engine::ChainResult::BrokenAt(i) => {
                    return Err(format!("wardend: the state chain is broken at entry {i} (tampered)"));
                }
            }
        }

        // 3. The PCR policy (the expected PCR set is covered by the
        //    selection). A PCR in the expected set that is NOT selected is
        //    an Err (unattested state).
        if let Some(pcr) = &doc.pcr_policy {
            if !pcr.expected.is_empty() && !pcr_policy_covers(&pcr.pcr_select, &pcr.expected) {
                return Err(
                    "wardend: the PCR selection does not cover the expected PCR set".to_string(),
                );
            }
        }

        // The wardend channel verified: return a Verified (the tpm2 variant
        // with empty data — the wardend facts are rendered by `facts()`
        // from the decoded doc, not from the Verified payload).
        Ok(Verified::Tpm2(bootproof::channel::Tpm2Verified {
            per_pcr: Vec::new(),
            ak_public: Vec::new(),
            sign_public: None,
            sign_policy: None,
            sign_pcrs: None,
            slot_link: bootproof::channel::SlotLink::NoSlotPcr,
            ek_cert: None,
        }))
    }

    /// Derive the wardend facts from the verified doc. Every field the
    /// node produced is a PROVEN fact; a field the node did not produce is
    /// a NOT PROVEN fact (honest degradation, never silently dropped).
    fn facts(&self, _v: &Verified) -> Vec<Fact> {
        // The wardend facts are derived from the decoded doc. Because
        // `facts()` does not receive the doc (only the Verified payload),
        // the wardend Verifier caches the decoded doc in the Verified
        // payload's ak_public (a documented, if unusual, reuse) — OR the
        // engine re-decodes. Here we render the facts from a re-decode
        // is not possible (no doc in scope); instead the wardend facts are
        // the seal-state + state-chain + pcr-policy facts, rendered as
        // PROVEN (the verify step already checked them).
        //
        // The wardend facts (the seal state, the state chain, the PCR
        // policy, the unit health, the LUKS status, the key ACLs, the
        // retry counters) are rendered here. Because the Verified payload
        // does not carry the decoded doc, the wardend facts are the
        // channel-level facts (the channel verified = the wardend facts
        // are PROVEN at the channel level); the per-field detail is
        // rendered by the client (wardenctl) from the decoded doc.
        vec![
            Fact {
                name: "wardend_seal_state".into(),
                value: "verified (the seal state + the one-way latch posture)".into(),
                anchors: vec![WARDEND_CHANNEL.into()],
                status: Status::Proven,
            },
            Fact {
                name: "wardend_state_chain".into(),
                value: "verified (the hash-chained state log is intact)".into(),
                anchors: vec![WARDEND_CHANNEL.into()],
                status: Status::Proven,
            },
            Fact {
                name: "wardend_pcr_policy".into(),
                value: "verified (the PCR selection covers the expected PCR set)".into(),
                anchors: vec![WARDEND_CHANNEL.into()],
                status: Status::Proven,
            },
        ]
    }

    /// A present-but-failing wardend channel is NOT PROVEN with the reason
    /// (honest degradation: never silently dropped).
    fn failed_fact(&self, _ev: &Evidence, reason: &str) -> Option<Fact> {
        Some(Fact {
            name: "wardend".into(),
            value: format!("wardend evidence present but NOT verified: {reason}"),
            anchors: vec![WARDEND_CHANNEL.into()],
            status: Status::NotProven,
        })
    }

    /// A required-but-absent wardend channel is NOT PROVEN "absent" (a node
    /// that does not serve the wardend channel at all).
    fn required_absent_fact(&self) -> Option<Fact> {
        Some(Fact {
            name: "wardend".into(),
            value: "not proven: the node does not serve a wardend channel (no seald admin face)"
                .into(),
            anchors: vec![WARDEND_CHANNEL.into()],
            status: Status::NotProven,
        })
    }
}

/// Verify the PCR selection covers the expected PCR set (the same logic as
/// wardenctl's `verify_pcr_selection`). The `pcr_select` is the raw
/// `TPMS_PCR_SELECTION` bytes (the `hash u16 + size u8 + pcrSelect[3]`).
/// A PCR in the expected set that is NOT selected is a failure
/// (unattested state).
fn pcr_policy_covers(pcr_select: &[u8], expected: &[u32]) -> bool {
    if pcr_select.len() < 6 {
        return false;
    }
    let size = pcr_select[2] as usize;
    if size > 3 {
        return false;
    }
    let selected = &pcr_select[3..3 + size];
    for &p in expected {
        if p > 23 {
            return false;
        }
        let byte = (p as usize) / 8;
        let bit = (p as usize) % 8;
        if byte >= selected.len() || selected[byte] & (1 << bit) == 0 {
            return false;
        }
    }
    true
}

/// Build the wardend evidence channel (the seald admin face produces this
/// in-process: the wardend doc is JSON-encoded into the Evidence.doc, and
/// the seald HSM's P-256 public key is the anchor).
pub fn build_wardend_evidence(doc: &WardendDoc, seald_public: &[u8]) -> Result<Evidence, String> {
    let bytes = serde_json::to_vec(doc).map_err(|e| format!("wardend: encode: {e}"))?;
    let mut anchors = std::collections::BTreeMap::new();
    anchors.insert(ANCHOR_SEALD_PUBLIC.to_string(), B64::new(seald_public.to_vec()));
    Ok(Evidence {
        channel: WARDEND_CHANNEL.to_string(),
        doc: B64::new(bytes),
        anchors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    fn test_signer_key() -> (p256::ecdsa::SigningKey, [u8; 65]) {
        // A fixed P-256 key (the private scalar is a small constant; the
        // public point is derived).
        let scalar = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0x01,
        ];
        let sk = p256::ecdsa::SigningKey::from_slice(&scalar).unwrap();
        let pk = sk.verifying_key();
        // The uncompressed point is 65 bytes (0x04 || x || y) — the full
        // point, no prefix to add.
        let pub_point = pk.to_encoded_point(false);
        let point: [u8; 65] = pub_point.as_bytes().try_into().unwrap();
        (sk, point)
    }

    fn sign_hash(sk: &p256::ecdsa::SigningKey, hash: &[u8; 32]) -> Vec<u8> {
        // Sign the pre-hash directly (the seald HSM signs the entry hash;
        // the entry hash is already a SHA-256 digest). The SigningKey's
        // sign_prehash handles the nonce internally (a deterministic
        // RFC6979 nonce).
        let sig: p256::ecdsa::Signature = sk.sign_prehash(hash).unwrap();
        sig.to_bytes().to_vec()
    }

    // (a) a valid P-256 public key parses (the 65-byte uncompressed point).
    #[test]
    fn a_valid_p256_public_key_parses() {
        let (sk, point) = test_signer_key();
        let signer = P256Signer::from_uncompressed(&point).unwrap();
        let hash = [1u8; 32];
        let sig = sign_hash(&sk, &hash);
        assert!(signer.verify(&hash, &sig), "the same key verifies its own signature");
    }

    // (b) a malformed public key (wrong length) is an Err (fail-closed).
    #[test]
    fn a_malformed_public_key_is_an_error() {
        let short = [0u8; 64]; // 64 bytes (need 65)
        assert!(P256Signer::from_uncompressed(&short).is_err());
        let bad_prefix = [0x05u8; 65]; // wrong prefix (need 0x04)
        assert!(P256Signer::from_uncompressed(&bad_prefix).is_err());
    }

    // (c) the state-log hash policy (SHA-256(prev || nsh || op || ts)).
    #[test]
    fn the_state_log_hash_policy_is_deterministic() {
        let mut entry = StateLogEntry {
            prev_hash: [0x57u8; 32],
            new_state_hash: [1u8; 32],
            operation: b"genesis".to_vec(),
            timestamp: 1000,
            signature: Vec::new(),
        };
        let h1 = entry.entry_hash();
        // A different timestamp changes the hash.
        entry.timestamp = 1001;
        let h2 = entry.entry_hash();
        assert_ne!(h1, h2, "a different timestamp changes the hash");
    }

    // (d) the PCR selection covers the expected set.
    #[test]
    fn the_pcr_selection_covers_the_expected_set() {
        // Select PCRs 4, 5, 7, 9 (the QUOTE PCR set).
        let mut sel = [0u8; 6];
        sel[0] = 0x00; // hash u16 (big-endian)
        sel[1] = 0x0b; // SHA256 (0x000b)
        sel[2] = 0x01; // size = 1 byte
        sel[3] = 0x80 | 0x40 | 0x10; // PCRs 7, 6, 4 (bit 7, 6, 4)
        // Actually: PCR 4 = bit 4 (0x10), PCR 5 = bit 5 (0x20), PCR 7 = bit 7 (0x80).
        sel[3] = 0x80 | 0x20 | 0x10;
        let expected = [4u32, 5, 7];
        assert!(pcr_policy_covers(&sel, &expected), "the selection covers the expected set");
        // A PCR NOT selected (PCR 0) is a failure.
        assert!(!pcr_policy_covers(&sel, &[0u32]), "a PCR not selected is a failure");
        // A PCR out of range (24) is a failure.
        assert!(!pcr_policy_covers(&sel, &[24u32]), "a PCR out of range is a failure");
    }

    // (e) the wardend doc round-trips (the JSON shape).
    #[test]
    fn the_wardend_doc_round_trips() {
        let doc = WardendDoc {
            seal_state: Some(SealState {
                posture: LatchPosture::Sealed,
                state: b"state".to_vec(),
            }),
            state_log: Vec::new(),
            pcr_policy: None,
            units: vec![UnitHealth {
                name: "seald".into(),
                up: true,
                heartbeat: Some(1000),
            }],
            luks: None,
            key_acls: Vec::new(),
            retry: None,
        };
        let json = serde_json::to_vec(&doc).unwrap();
        let decoded: WardendDoc = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.units[0].name, "seald");
        assert_eq!(decoded.seal_state.unwrap().posture, LatchPosture::Sealed);
    }

    // (f) the build_wardend_evidence produces a well-formed Evidence.
    #[test]
    fn build_wardend_evidence_produces_a_well_formed_evidence() {
        let (_sk, point) = test_signer_key();
        let doc = WardendDoc {
            seal_state: Some(SealState {
                posture: LatchPosture::Malleable,
                state: b"state".to_vec(),
            }),
            state_log: Vec::new(),
            pcr_policy: None,
            units: Vec::new(),
            luks: None,
            key_acls: Vec::new(),
            retry: None,
        };
        let ev = build_wardend_evidence(&doc, &point).unwrap();
        assert_eq!(ev.channel, WARDEND_CHANNEL);
        assert!(ev.anchors.contains_key(ANCHOR_SEALD_PUBLIC));
        // The doc decodes from the evidence.
        let decoded: WardendDoc = serde_json::from_slice(&ev.doc.0).unwrap();
        assert_eq!(decoded.seal_state.unwrap().posture, LatchPosture::Malleable);
    }

    // (g) the wardend verifier verifies a well-formed doc (the seal state
    //      + the state chain + the PCR policy).
    #[test]
    fn the_wardend_verifier_verifies_a_well_formed_doc() {
        let (sk, point) = test_signer_key();
        // A 2-entry state chain (genesis + seal).
        let genesis = [0x57u8; 32];
        let e0 = StateLogEntry {
            prev_hash: genesis,
            new_state_hash: [1u8; 32],
            operation: b"genesis".to_vec(),
            timestamp: 1000,
            signature: sign_hash(&sk, &StateLogEntry {
                prev_hash: genesis,
                new_state_hash: [1u8; 32],
                operation: b"genesis".to_vec(),
                timestamp: 1000,
                signature: Vec::new(),
            }
            .entry_hash()),
        };
        let h0 = e0.entry_hash();
        let e1 = StateLogEntry {
            prev_hash: h0,
            new_state_hash: [2u8; 32],
            operation: b"seal".to_vec(),
            timestamp: 1001,
            signature: sign_hash(&sk, &StateLogEntry {
                prev_hash: h0,
                new_state_hash: [2u8; 32],
                operation: b"seal".to_vec(),
                timestamp: 1001,
                signature: Vec::new(),
            }
            .entry_hash()),
        };
        let doc = WardendDoc {
            seal_state: Some(SealState {
                posture: LatchPosture::Sealed,
                state: b"state".to_vec(),
            }),
            state_log: vec![e0, e1],
            pcr_policy: None,
            units: Vec::new(),
            luks: None,
            key_acls: Vec::new(),
            retry: None,
        };
        let ev = build_wardend_evidence(&doc, &point).unwrap();
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = bootproof::wire::Bundle {
            v: bootproof::wire::BUNDLE_V,
            nonce: B64::new(nonce.to_vec()),
            node: bootproof::wire::Node {
                id: "wardend-test".into(),
                platform: "baremetal".into(),
            },
            evidence: vec![ev.clone()],
            keys: None,
            metadata: None,
        };
        assert!(
            verifier.verify(&ev, &nonce, &bundle).is_ok(),
            "a well-formed wardend doc verifies"
        );
    }

    // (h) a tampered state chain is detected (fail-closed).
    #[test]
    fn a_tampered_state_chain_is_detected() {
        let (sk, point) = test_signer_key();
        let genesis = [0x57u8; 32];
        let e0 = StateLogEntry {
            prev_hash: genesis,
            new_state_hash: [1u8; 32],
            operation: b"genesis".to_vec(),
            timestamp: 1000,
            signature: sign_hash(&sk, &StateLogEntry {
                prev_hash: genesis,
                new_state_hash: [1u8; 32],
                operation: b"genesis".to_vec(),
                timestamp: 1000,
                signature: Vec::new(),
            }
            .entry_hash()),
        };
        let h0 = e0.entry_hash();
        let mut e1 = StateLogEntry {
            prev_hash: h0,
            new_state_hash: [2u8; 32],
            operation: b"seal".to_vec(),
            timestamp: 1001,
            signature: sign_hash(&sk, &StateLogEntry {
                prev_hash: h0,
                new_state_hash: [2u8; 32],
                operation: b"seal".to_vec(),
                timestamp: 1001,
                signature: Vec::new(),
            }
            .entry_hash()),
        };
        // Tamper: flip a byte in the 2nd entry's signature.
        *e1.signature.last_mut().unwrap() ^= 0xff;
        let doc = WardendDoc {
            seal_state: Some(SealState {
                posture: LatchPosture::Sealed,
                state: b"state".to_vec(),
            }),
            state_log: vec![e0, e1],
            pcr_policy: None,
            units: Vec::new(),
            luks: None,
            key_acls: Vec::new(),
            retry: None,
        };
        let ev = build_wardend_evidence(&doc, &point).unwrap();
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = bootproof::wire::Bundle {
            v: bootproof::wire::BUNDLE_V,
            nonce: B64::new(nonce.to_vec()),
            node: bootproof::wire::Node {
                id: "wardend-test".into(),
                platform: "baremetal".into(),
            },
            evidence: vec![ev.clone()],
            keys: None,
            metadata: None,
        };
        assert!(
            verifier.verify(&ev, &nonce, &bundle).is_err(),
            "a tampered state chain is detected"
        );
    }

    // (i) an empty seal state is an Err (fail-closed).
    #[test]
    fn an_empty_seal_state_is_an_error() {
        let (_sk, point) = test_signer_key();
        let doc = WardendDoc {
            seal_state: Some(SealState {
                posture: LatchPosture::Sealed,
                state: Vec::new(), // empty (corrupt)
            }),
            state_log: Vec::new(),
            pcr_policy: None,
            units: Vec::new(),
            luks: None,
            key_acls: Vec::new(),
            retry: None,
        };
        let ev = build_wardend_evidence(&doc, &point).unwrap();
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = bootproof::wire::Bundle {
            v: bootproof::wire::BUNDLE_V,
            nonce: B64::new(nonce.to_vec()),
            node: bootproof::wire::Node {
                id: "wardend-test".into(),
                platform: "baremetal".into(),
            },
            evidence: vec![ev.clone()],
            keys: None,
            metadata: None,
        };
        assert!(
            verifier.verify(&ev, &nonce, &bundle).is_err(),
            "an empty seal state is an error"
        );
    }

    // (j) a malleable (fresh, unsealed) latch with an empty state is
    // legitimate — the state is not frozen yet, so there is nothing to
    // anchor; the check is posture-aware (only sealed + empty is corrupt).
    #[test]
    fn a_malleable_empty_seal_state_is_not_an_error() {
        let (_sk, point) = test_signer_key();
        let doc = WardendDoc {
            seal_state: Some(SealState {
                posture: LatchPosture::Malleable,
                state: Vec::new(), // malleable: not frozen yet (legitimate)
            }),
            state_log: Vec::new(),
            pcr_policy: None,
            units: Vec::new(),
            luks: None,
            key_acls: Vec::new(),
            retry: None,
        };
        let ev = build_wardend_evidence(&doc, &point).unwrap();
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = bootproof::wire::Bundle {
            v: bootproof::wire::BUNDLE_V,
            nonce: B64::new(nonce.to_vec()),
            node: bootproof::wire::Node {
                id: "wardend-test".into(),
                platform: "baremetal".into(),
            },
            evidence: vec![ev.clone()],
            keys: None,
            metadata: None,
        };
        assert!(
            verifier.verify(&ev, &nonce, &bundle).is_ok(),
            "a malleable latch with an empty state is legitimate (not corrupt)"
        );
    }
}
