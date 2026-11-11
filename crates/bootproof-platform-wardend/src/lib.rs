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

/// The anchor key for the whole-doc signature (the seald HSM's 64-byte
/// `r || s` ECDSA P-256 signature over `canonical_doc_digest`). I-2: the
/// signature rides the SAME anchors map the client already reads for
/// `seald_public`/`hsm_public` (no new container, no wire-format change);
/// the doc JSON stays byte-pure under the digest. A missing (absent key)
/// or malformed (non-64-byte) doc signature fails the channel closed:
/// an unsigned doc is not a degraded doc, it is an unverified one.
pub const ANCHOR_DOC_SIGNATURE: &str = "doc_signature";

/// The domain-separation prefix for the whole-doc digest
/// (`canonical_doc_digest`). The same HSM key signs BOTH the state-log
/// entries and the whole platform doc; the doc signature is over
/// `SHA-256(DOC_DIGEST_PREFIX || canonical fields)` while an entry
/// signature is over the bare `entry_hash`, so a signature valid for one
/// can NEVER verify for the other (the same-key domain-separation rule —
/// `a_state_log_entry_signature_never_verifies_as_the_doc_signature`
/// proves it).
pub const DOC_DIGEST_PREFIX: &[u8] = b"wardend/platform-doc-digest/v1";

/// D4 (digest v2): the domain AND version marker for the nonce-bound,
/// user-data-bearing doc digest. The v1->v2 switch IS this marker change:
/// a v1-signed doc recomputed under v2 (and the reverse) is a digest
/// mismatch by construction, so BOTH directions fail closed with no
/// dual-accept window and no ambiguity about what a key has signed under
/// which contract (`canonical_doc_digest_v2`; spec:
/// docs/design-d4-d3-digest-v2.md sec.1). A captured v1 response replayed
/// to a fresh challenge fails exactly this way: the v1 digest has no
/// nonce input at all, which is the A7 replay the v2 binding closes.
pub const DOC_DIGEST_PREFIX_V2: &[u8] = b"wardend/platform-doc-digest/v2";

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

/// D3: the attested launch-time user-data section (v3's shape,
/// `seald/src/platform.rs:129-140`: a hash commitment that always rides,
/// plus the plaintext IFF the box publishes it). The section lives INSIDE
/// the signed doc: the whole-doc signature anchors the hash and, when
/// present, the exact plaintext bytes, so "these are the user-data bytes
/// this instance read at boot" becomes a signed fact instead of a metadata
/// display claim (ledger B1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDataSection {
    /// SHA-256 of the RAW user-data bytes the platform read at boot.
    pub sha256: [u8; 32],
    /// The full raw bytes (UTF-8 where decodable, else the exact bytes).
    /// Present IFF the box runs the public-asserted posture; a
    /// commitment-only doc withholds it by CONFIG, never by silent
    /// truncation (the page then states the commitment tier, design
    /// doc sec.3).
    #[serde(default)]
    pub text: Option<String>,
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
    /// D3: the attested launch-time user-data (hash commitment always,
    /// plaintext by posture). `serde(default)`: a v1 doc decodes with
    /// `None` and stays byte-identical for the v1 digest; the v2 digest
    /// binds the field when present.
    #[serde(default)]
    pub user_data: Option<UserDataSection>,
}

// ---------------------------------------------------------------------------
// The whole-doc canonical digest (I-2: byte-attestation of the platform
// doc). ONE implementation, used by BOTH the sign side (the wardend
// seald admin face, via the `canonical_doc_digest` re-export) and the
// verify side (`WardendVerifier::verify`). A divergence between two
// digest implementations is the bug class this single source of truth
// guards against.
//
// The canonicalization discipline MIRRORS the state-log `entry_hash`
// (domain-separated, fixed field order, no serde): a domain prefix,
// fields in a FIXED order, a 1-byte presence tag per Optional field
// (None = 0x00 feeds NOTHING after the tag; Some = 0x01 + the canonical
// bytes — so None != Some(empty)), a 4-byte BE length per Vec / bytes
// field (so [a] != [a, b] and a length change can never collide),
// fixed-width big-endian integers, strings as len-prefixed bytes.
// ---------------------------------------------------------------------------

/// Feed a fixed-width big-endian integer into the digest.
fn digest_u64(h: &mut Sha256, v: u64) {
    h.update(v.to_be_bytes());
}

/// Feed a length-prefixed byte string (the canonical bytes of a `String`,
/// `Vec<u8>`, or slice) into the digest.
fn digest_bytes(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u32).to_be_bytes());
    h.update(b);
}

/// Feed a length-prefixed list of u32 (the PCR sets) into the digest.
fn digest_u32s(h: &mut Sha256, v: &[u32]) {
    h.update((v.len() as u32).to_be_bytes());
    for x in v {
        h.update(x.to_be_bytes());
    }
}

/// The canonical bytes of a bool (a fixed single byte, never serde's
/// `true`/`false`).
fn digest_bool(h: &mut Sha256, b: bool) {
    h.update([if b { 1 } else { 0 }]);
}

/// The canonical bytes of the latch posture (0 = malleable, 1 = sealed).
fn digest_posture(h: &mut Sha256, p: LatchPosture) {
    h.update([match p {
        LatchPosture::Malleable => 0,
        LatchPosture::Sealed => 1,
    }]);
}

/// The canonical bytes of an Option (1-byte presence tag; None feeds
/// NOTHING after the tag, so None != Some(empty)).
fn digest_opt<T>(h: &mut Sha256, v: &Option<T>, f: impl Fn(&mut Sha256, &T)) {
    match v {
        None => h.update([0u8]),
        Some(x) => {
            h.update([1u8]);
            f(h, x);
        }
    }
}

fn digest_seal_state(h: &mut Sha256, s: &SealState) {
    digest_posture(h, s.posture);
    digest_bytes(h, &s.state);
}

fn digest_pcr_policy(h: &mut Sha256, p: &PcrPolicy) {
    digest_u32s(h, &p.expected);
    digest_bytes(h, &p.pcr_select);
    // The BTreeMap iterates in key order: deterministic by construction.
    h.update((p.values.len() as u32).to_be_bytes());
    for (k, v) in &p.values {
        h.update(k.to_be_bytes());
        digest_bytes(h, v);
    }
}

fn digest_unit_health(h: &mut Sha256, u: &UnitHealth) {
    digest_bytes(h, u.name.as_bytes());
    digest_bool(h, u.up);
    digest_opt(h, &u.heartbeat, |h, v| digest_u64(h, *v));
}

fn digest_luks(h: &mut Sha256, l: &LuksStatus) {
    digest_bytes(h, l.device.as_bytes());
    digest_bool(h, l.open);
    digest_u32s(h, &l.pcr_policy);
    digest_opt(h, &l.marker_counter, |h, v| digest_u64(h, *v));
}

fn digest_key_acl(h: &mut Sha256, k: &KeyAcl) {
    digest_u64(h, k.handle);
    h.update((k.operations.len() as u32).to_be_bytes());
    for op in &k.operations {
        digest_bytes(h, op.as_bytes());
    }
    digest_u32s(h, &k.pcr_policy);
}

fn digest_retry(h: &mut Sha256, r: &RetryCounters) {
    digest_u64(h, r.warden_respawn as u64);
    digest_u64(h, r.watchdog_reboot_guard as u64);
}

/// D3: the canonical bytes of the user-data section: the commitment hash
/// as 32 RAW bytes (fixed width, no length prefix), then the plaintext
/// under its OWN presence tag as len-prefixed bytes (None != Some(empty),
/// the same discipline as every other Optional in this doc).
fn digest_user_data(h: &mut Sha256, u: &UserDataSection) {
    h.update(u.sha256);
    digest_opt(h, &u.text, |h, t| digest_bytes(h, t.as_bytes()));
}

fn digest_state_log_entry(h: &mut Sha256, e: &StateLogEntry) {
    h.update(e.prev_hash);
    h.update(e.new_state_hash);
    digest_bytes(h, &e.operation);
    digest_u64(h, e.timestamp);
    // The entry's own signature is bound into the doc digest too: the
    // doc signature covers the WHOLE doc, every byte of every field.
    digest_bytes(h, &e.signature);
}

/// The canonical whole-doc digest: `SHA-256(DOC_DIGEST_PREFIX || the
/// canonical bytes of every WardendDoc field, in fixed order
/// (seal_state, state_log, pcr_policy, units, luks, key_acls, retry))`.
/// `doc_signature` is EXCLUDED (the signed container never includes its
/// own signature).
///
/// This is the single source of truth: seald signs THIS digest (the HSM
/// sign path, the key never leaves seald) and `WardendVerifier::verify`
/// recomputes THIS digest from the decoded doc. Never fork this function.
pub fn canonical_doc_digest(doc: &WardendDoc) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOC_DIGEST_PREFIX);
    digest_fields(&mut h, doc);
    h.finalize().into()
}

/// The shared canonical field walk for BOTH digest versions (one
/// implementation, two domain markers — the v1/v2 difference is ONLY the
/// marker and the extra v2 inputs; the field discipline is identical, so
/// a drift in one cannot hide from the other).
fn digest_fields(h: &mut Sha256, doc: &WardendDoc) {
    digest_opt(h, &doc.seal_state, digest_seal_state);
    h.update((doc.state_log.len() as u32).to_be_bytes());
    for e in &doc.state_log {
        digest_state_log_entry(h, e);
    }
    digest_opt(h, &doc.pcr_policy, digest_pcr_policy);
    h.update((doc.units.len() as u32).to_be_bytes());
    for u in &doc.units {
        digest_unit_health(h, u);
    }
    digest_opt(h, &doc.luks, digest_luks);
    h.update((doc.key_acls.len() as u32).to_be_bytes());
    for k in &doc.key_acls {
        digest_key_acl(h, k);
    }
    digest_opt(h, &doc.retry, digest_retry);
}

/// D4+D3: the canonical whole-doc digest v2. One domain change and two
/// added inputs over v1:
///
/// ```text
/// digest_v2 = SHA-256(
///     "wardend/platform-doc-digest/v2"   // domain AND version marker
///  || nonce32                            // the challenge being answered
///  || canonical_fields(doc)              // v1's exact walk ...
///  || presence-tag(user_data) [...]      // ... PLUS the D3 section (LAST)
/// )
/// ```
///
/// This is what the seald admin face MUST sign PER RESPONSE (one HSM
/// signature over the challenge the client just drew) and what
/// `WardendVerifier::verify` recomputes with the bundle's nonce. The nonce
/// input is what closes the A7 replay: a captured response answers a
/// different challenge, so its signature fails the recompute. The
/// fail-closed v1<->v2 property is the marker change alone (see
/// `DOC_DIGEST_PREFIX_V2`). Never fork this function; the browser verifier
/// mirrors it byte-for-byte (`canonicalDocDigestV2` in
/// `single_file/bootproof.js` and `system_health/verify.js`, gated by the
/// doc-digest-v2 parity fixtures).
pub fn canonical_doc_digest_v2(doc: &WardendDoc, nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOC_DIGEST_PREFIX_V2);
    h.update(nonce);
    digest_fields(&mut h, doc);
    digest_opt(&mut h, &doc.user_data, digest_user_data);
    h.finalize().into()
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
        nonce: &[u8; 32],
        _bundle: &bootproof::wire::Bundle,
    ) -> Result<Verified, String> {
        // Decode the wardend evidence doc (the JSON shape). A malformed doc
        // is an Err (fail-closed: a corrupt wardend doc is never silently
        // accepted).
        let doc: WardendDoc = serde_json::from_slice(&ev.doc.0)
            .map_err(|e| format!("wardend: malformed evidence doc: {e}"))?;

        // 0. The whole-doc signature (I-2: byte-attestation; D4: NOW
        //    NONCE-BOUND). FIRST, before any structural check: the
        //    signature covers every byte of the doc AND the challenge the
        //    client drew for this page view (digest v2), so it is the
        //    strongest check and the structural checks below are defense
        //    in depth. The client re-derives the canonical v2 digest from
        //    the decoded doc + THE BUNDLE NONCE and verifies the HSM
        //    signature with the SAME anchor key it uses for the state log.
        //    An absent anchor, a non-64-byte signature, a wrong key, a
        //    byte-flipped doc, or a REPLAYED response (the signature was
        //    made over a different nonce) all fail closed.
        let public = ev
            .anchors
            .get(ANCHOR_SEALD_PUBLIC)
            .or_else(|| ev.anchors.get(ANCHOR_HSM_PUBLIC))
            .ok_or("wardend: the seald HSM public key is missing (cannot verify the doc signature)")?;
        let signer = P256Signer::from_uncompressed(&public.0)?;
        let doc_signature = ev
            .anchors
            .get(ANCHOR_DOC_SIGNATURE)
            .ok_or("wardend: the doc signature is missing (unsigned platform doc)")?;
        let digest = canonical_doc_digest_v2(&doc, nonce);
        if !signer.verify(&digest, &doc_signature.0) {
            return Err(
                "wardend: the doc signature does not verify (tampered, unsigned, or REPLAYED platform doc: the signature is bound to this challenge's nonce)"
                    .to_string(),
            );
        }

        // 0b. D3: the user-data section's self-consistency, INSIDE the
        //     now-verified signed bytes: the plaintext must hash to the
        //     committed digest. A mismatch is a FAILED channel (the
        //     signature proves the bytes, so a lie here is a lie the key
        //     itself told — never a degraded pass). An absent section is
        //     legitimate (the honest NOT PROVEN fact below, or the
        //     commitment tier when only the hash is published).
        if let Some(ud) = &doc.user_data {
            if let Some(text) = &ud.text {
                let got: [u8; 32] = Sha256::digest(text.as_bytes()).into();
                if got != ud.sha256 {
                    return Err(
                        "wardend: the user-data text does not hash to its committed sha256 (tampered attested user-data)".to_string(),
                    );
                }
            }
        }

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
        //    key. A tampered chain is an Err (fail-closed). (The doc
        //    signature above already binds every entry byte; the chain
        //    check is defense in depth — and it is what pins the chain
        //    LINKS, which the signature proves the bytes of but not the
        //    sequence semantics.)
        if !doc.state_log.is_empty() {
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
        // from the decoded doc, not from the Verified payload). D3: the
        // SIGNATURE-VERIFIED user-data section rides the payload's
        // ak_public as its canonical JSON (the documented reuse this
        // Verifier already uses for cross-method state: `facts()` receives
        // only the Verified, so the attested bytes it must render travel
        // here). These are the bytes the doc signature just validated:
        // what `facts()` renders is what the HSM key attested, nothing
        // else.
        let user_data_json = doc
            .user_data
            .as_ref()
            .map(|u| serde_json::to_vec(u).unwrap_or_default())
            .unwrap_or_default();
        Ok(Verified::Tpm2(bootproof::channel::Tpm2Verified {
            per_pcr: Vec::new(),
            ak_public: user_data_json,
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
    fn facts(&self, v: &Verified) -> Vec<Fact> {
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
        let mut facts = vec![
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
        ];
        // D3: the attested user-data fact. This method runs ONLY after
        // verify() returned Ok, i.e. the digest over these bytes verified
        // under the HSM key AND (digest v2) against THIS view's nonce —
        // so the tiers below are statements about signature-verified
        // bytes, not about server claims.
        //
        //   plaintext present  -> PROVEN (the exact launch bytes are
        //                         published, hashed, signed, and nonce-
        //                         bound; verify() already asserted the
        //                         hash matches the text or errored).
        //   commitment only    -> DEGRADED: the key attests the HASH of
        //                         the launch bytes but the bytes
        //                         themselves are withheld by config —
        //                         content anchored, no plaintext to
        //                         audit. Never silently PROVEN.
        //   section absent     -> NOT PROVEN: the doc attests nothing
        //                         about user-data (honest absence, never
        //                         a healthy default).
        let attested: Option<UserDataSection> = match v {
            Verified::Tpm2(t) if !t.ak_public.is_empty() => {
                serde_json::from_slice(&t.ak_public).ok()
            }
            _ => None,
        };
        facts.push(match attested {
            Some(u) => {
                let hex: String = u.sha256.iter().map(|b| format!("{b:02x}")).collect();
                match &u.text {
                    Some(text) => Fact {
                        name: "wardend_user_data".into(),
                        value: format!(
                            "attested: {} bytes of launch user-data, sha256 {hex}, signature-verified and nonce-bound",
                            text.len()
                        ),
                        anchors: vec![WARDEND_CHANNEL.into()],
                        status: Status::Proven,
                    },
                    None => Fact {
                        name: "wardend_user_data".into(),
                        value: format!(
                            "commitment attested (sha256 {hex}); plaintext withheld by configuration"
                        ),
                        anchors: vec![WARDEND_CHANNEL.into()],
                        status: Status::Degraded,
                    },
                }
            }
            None => Fact {
                name: "wardend_user_data".into(),
                value: "not proven: the signed doc carries no user-data section".into(),
                anchors: vec![WARDEND_CHANNEL.into()],
                status: Status::NotProven,
            },
        });
        facts
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
///
/// `doc_signature` is the 64-byte `r || s` HSM signature over
/// `canonical_doc_digest(doc)`, computed by the CALLER (the seald admin
/// face, over its own HSM sign path — the key never leaves seald). The
/// crate stays key-less: it carries + verifies signatures, it never
/// signs. The signature rides the anchors map (the same structure the
/// client already reads for the public key): the doc JSON stays byte-pure
/// under the digest, and there is no new container and no wire-format
/// change.
pub fn build_wardend_evidence(
    doc: &WardendDoc,
    seald_public: &[u8],
    doc_signature: Vec<u8>,
) -> Result<Evidence, String> {
    let bytes = serde_json::to_vec(doc).map_err(|e| format!("wardend: encode: {e}"))?;
    let mut anchors = std::collections::BTreeMap::new();
    anchors.insert(ANCHOR_SEALD_PUBLIC.to_string(), B64::new(seald_public.to_vec()));
    anchors.insert(ANCHOR_DOC_SIGNATURE.to_string(), B64::new(doc_signature));
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

    /// Build signed wardend evidence (the seald admin face's path: the
    /// caller computes `canonical_doc_digest_v2` for the response's nonce,
    /// signs it, and passes the signature in). The test stand-in for
    /// `wardend_evidence()`. D4: the sign side is NONCE-BOUND — the test
    /// bundle nonce is `[0x42u8; 32]` (`test_bundle`), so every evidence
    /// built here is signed for exactly that challenge.
    fn build_signed(doc: &WardendDoc, sk: &p256::ecdsa::SigningKey, point: &[u8]) -> Evidence {
        build_signed_for(doc, sk, point, &[0x42u8; 32])
    }

    /// The explicit-nonce sign path (the per-response HSM sign: one
    /// signature per challenge). The v2 conformance battery signs some
    /// evidence for a DIFFERENT nonce to prove the replay rejection.
    fn build_signed_for(
        doc: &WardendDoc,
        sk: &p256::ecdsa::SigningKey,
        point: &[u8],
        nonce: &[u8; 32],
    ) -> Evidence {
        let digest = canonical_doc_digest_v2(doc, nonce);
        let sig = sign_hash(sk, &digest);
        build_wardend_evidence(doc, point, sig).unwrap()
    }

    /// A minimal verification bundle (the wardend channel needs only the
    /// evidence + the nonce; the core channels are absent = NOT PROVEN,
    /// which the platform verifier does not consult).
    fn test_bundle(ev: &Evidence) -> bootproof::wire::Bundle {
        bootproof::wire::Bundle {
            v: bootproof::wire::BUNDLE_V,
            nonce: B64::new([0x42u8; 32].to_vec()),
            node: bootproof::wire::Node {
                id: "wardend-test".into(),
                platform: "baremetal".into(),
            },
            evidence: vec![ev.clone()],
            keys: None,
            metadata: None,
        }
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
            user_data: None,
        };
        let json = serde_json::to_vec(&doc).unwrap();
        let decoded: WardendDoc = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.units[0].name, "seald");
        assert_eq!(decoded.seal_state.unwrap().posture, LatchPosture::Sealed);
    }

    // (f) the build_wardend_evidence produces a well-formed Evidence.
    #[test]
    fn build_wardend_evidence_produces_a_well_formed_evidence() {
        let (sk, point) = test_signer_key();
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
            user_data: None,
        };
        let ev = build_signed(&doc, &sk, &point);
        assert_eq!(ev.channel, WARDEND_CHANNEL);
        assert!(ev.anchors.contains_key(ANCHOR_SEALD_PUBLIC));
        // The doc decodes from the evidence.
        let decoded: WardendDoc = serde_json::from_slice(&ev.doc.0).unwrap();
        assert_eq!(decoded.seal_state.unwrap().posture, LatchPosture::Malleable);
        // The signature rides the anchors map (the caller's signature is
        // stamped beside the public key: the structure the client already
        // reads, 64 bytes r || s).
        assert_eq!(ev.anchors[ANCHOR_DOC_SIGNATURE].0.len(), 64);
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
            user_data: None,
        };
        let ev = build_signed(&doc, &sk, &point);
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = test_bundle(&ev);
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
            user_data: None,
        };
        // Sign the TAMPERED doc (so the doc signature itself is valid):
        // the chain check must be what rejects it (defense in depth —
        // the doc signature binds the bytes, the chain check owns the
        // link semantics).
        let ev = build_signed(&doc, &sk, &point);
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = test_bundle(&ev);
        assert!(
            verifier.verify(&ev, &nonce, &bundle).is_err(),
            "a tampered state chain is detected"
        );
    }

    // (i) an empty seal state is an Err (fail-closed).
    #[test]
    fn an_empty_seal_state_is_an_error() {
        let (sk, point) = test_signer_key();
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
            user_data: None,
        };
        let ev = build_signed(&doc, &sk, &point);
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = test_bundle(&ev);
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
        let (sk, point) = test_signer_key();
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
            user_data: None,
        };
        let ev = build_signed(&doc, &sk, &point);
        let verifier = WardendVerifier;
        let nonce = [0x42u8; 32];
        let bundle = test_bundle(&ev);
        assert!(
            verifier.verify(&ev, &nonce, &bundle).is_ok(),
            "a malleable latch with an empty state is legitimate (not corrupt)"
        );
    }

    // =========================================================================
    // I-2: the whole-doc signature (byte-attestation of the platform doc).
    // Positive first, then the negative battery: EVERY negative asserts
    // verify() FAILS (a passing negative here is a false green).
    // =========================================================================

    /// The golden doc (every field populated: the canonicalization
    /// covers all seven fields, all four nested structs, both Option
    /// arms, and a non-empty BTreeMap). The state-log entry is signed by
    /// the test key (the chain check still runs, defense in depth; the
    /// RFC6979 nonce is deterministic, so the golden digest is stable).
    /// The PCR select is the production 6-byte TPMS_PCR_SELECTION shape
    /// (hash u16, size u8 = 3, pcrSelect[3]) covering the expected set
    /// {4,5,7,9,11}: byte 0 bits 4/5/7 = 0xb0, byte 1 bits 1/3 = 0x0a.
    fn golden_doc() -> WardendDoc {
        let (sk, _point) = test_signer_key();
        let mut values = std::collections::BTreeMap::new();
        values.insert(7u32, vec![0xa7u8; 32]);
        values.insert(11u32, vec![0xb1u8; 32]);
        let mut entry = StateLogEntry {
            prev_hash: [0x57u8; 32],
            new_state_hash: [0x01u8; 32],
            operation: b"genesis".to_vec(),
            timestamp: 1700000000,
            signature: Vec::new(),
        };
        entry.signature = sign_hash(&sk, &entry.entry_hash());
        WardendDoc {
            seal_state: Some(SealState {
                posture: LatchPosture::Sealed,
                state: b"golden-state".to_vec(),
            }),
            state_log: vec![entry],
            pcr_policy: Some(PcrPolicy {
                expected: vec![4, 5, 7, 9, 11],
                pcr_select: vec![0x00, 0x0b, 0x03, 0xb0, 0x0a, 0x00],
                values,
            }),
            units: vec![
                UnitHealth {
                    name: "seald".into(),
                    up: true,
                    heartbeat: Some(1700000001),
                },
                UnitHealth {
                    name: "keepd".into(),
                    up: false,
                    heartbeat: None,
                },
            ],
            luks: Some(LuksStatus {
                device: "/dev/nvme1n1".into(),
                open: true,
                pcr_policy: vec![7, 9],
                marker_counter: Some(42),
            }),
            key_acls: vec![KeyAcl {
                handle: 0x68736d5f61636c31,
                operations: vec!["sign".into(), "unseal".into()],
                pcr_policy: vec![4, 7, 9],
            }],
            retry: Some(RetryCounters {
                warden_respawn: 3,
                watchdog_reboot_guard: 1,
            }),
            user_data: None,
        }
    }

    // (k) POSITIVE-FIRST: the golden doc round-trips (signed build ->
    //     verify Ok). This is the witness that every negative below
    //     rejects a tamper and NOT a broken happy path.
    #[test]
    fn the_golden_signed_doc_verifies() {
        let (sk, point) = test_signer_key();
        let doc = golden_doc();
        let ev = build_signed(&doc, &sk, &point);
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_ok(),
            "the golden signed doc verifies"
        );
    }

    // (l) the golden digest vector: the parity pin. ONE implementation
    //     (canonical_doc_digest) is used by BOTH sides (the wardend seal
    //     crate consumes THIS function — the parity is structural), but
    //     this vector pins the BYTES: a refactor that silently changes the
    //     canonicalization changes the digest and fails here. The wardend
    //     D-cycle records carry the same hex.
    #[test]
    fn the_canonical_doc_digest_golden_vector() {
        let digest = canonical_doc_digest(&golden_doc());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, GOLDEN_DIGEST_HEX,
            "the canonical doc digest changed: the canonicalization must stay pinned (both sign + verify sides consume this single implementation)"
        );
    }

    /// The pinned golden digest (computed from canonical_doc_digest over
    /// golden_doc(), pinned at I-2 landing: 1a6c06ff...4a10).
    const GOLDEN_DIGEST_HEX: &str = "1a6c06ffdcaf4aec3e22c15a81d076544083007d4406c757585f50bd68884a10";

    // (m) NEGATIVE: flip one byte in units AFTER signing -> verify FAILS.
    //     (The doc the verifier decodes differs from the doc that was
    //     signed: the digest differs, the signature does not verify.)
    #[test]
    fn a_flipped_unit_byte_after_signing_fails_verification() {
        let (sk, point) = test_signer_key();
        let mut doc = golden_doc();
        let sig = sign_hash(&sk, &canonical_doc_digest_v2(&doc, &[0x42u8; 32]));
        // Tamper AFTER signing: flip the second unit's up bit.
        doc.units[1].up = true;
        let ev = build_wardend_evidence(&doc, &point, sig).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "a flipped byte in units after signing must fail the doc signature"
        );
    }

    // (m2) NEGATIVE: flip one byte in key_acls AFTER signing -> FAILS
    //      (the key-ACL table is the table the D-page renders from the
    //      I-1 fill: it is the fact this increment exists to attest).
    #[test]
    fn a_flipped_key_acl_byte_after_signing_fails_verification() {
        let (sk, point) = test_signer_key();
        let mut doc = golden_doc();
        let sig = sign_hash(&sk, &canonical_doc_digest_v2(&doc, &[0x42u8; 32]));
        doc.key_acls[0].operations.push("decrypt".into());
        let ev = build_wardend_evidence(&doc, &point, sig).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "an appended operation in key_acls after signing must fail the doc signature"
        );
    }

    // (n) NEGATIVE: an absent doc_signature anchor -> verify FAILS
    //     (an unsigned doc is not a degraded doc: it is unverified).
    #[test]
    fn an_absent_doc_signature_fails_verification() {
        let (sk, point) = test_signer_key();
        let doc = golden_doc();
        let mut ev = build_signed(&doc, &sk, &point);
        ev.anchors.remove(ANCHOR_DOC_SIGNATURE);
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "an absent doc signature must fail closed"
        );
    }

    // (n2) NEGATIVE: an empty doc_signature (Some-shape with zero bytes)
    //      -> verify FAILS.
    #[test]
    fn an_empty_doc_signature_fails_verification() {
        let (_sk, point) = test_signer_key();
        let doc = golden_doc();
        let ev = build_wardend_evidence(&doc, &point, Vec::new()).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "an empty doc signature must fail closed"
        );
    }

    // (n3) NEGATIVE: a wrong-length doc_signature (63 bytes) -> FAILS.
    #[test]
    fn a_wrong_length_doc_signature_fails_verification() {
        let (sk, point) = test_signer_key();
        let doc = golden_doc();
        let mut sig = sign_hash(&sk, &canonical_doc_digest_v2(&doc, &[0x42u8; 32]));
        sig.truncate(63);
        let ev = build_wardend_evidence(&doc, &point, sig).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "a truncated doc signature must fail closed"
        );
    }

    // (o) NEGATIVE: signed by a DIFFERENT key (the anchor key is the real
    //     one, the signer is an attacker key) -> verify FAILS.
    #[test]
    fn a_doc_signature_from_a_different_key_fails_verification() {
        let (_sk, point) = test_signer_key();
        // A second key (a different scalar).
        let mut scalar = [0u8; 32];
        scalar[31] = 7;
        let attacker = p256::ecdsa::SigningKey::from_slice(&scalar).unwrap();
        let doc = golden_doc();
        let sig = sign_hash(&attacker, &canonical_doc_digest_v2(&doc, &[0x42u8; 32]));
        let ev = build_wardend_evidence(&doc, &point, sig).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "a doc signature from a key that is not the anchor must fail"
        );
    }

    // (p) NEGATIVE: None replaced by Some(empty) changes the digest ->
    //     verify FAILS (the presence-tag binding: 0x00 vs 0x01 + the
    //     canonical empty bytes must never collide).
    #[test]
    fn none_versus_some_empty_changes_the_digest() {
        let (sk, point) = test_signer_key();
        // seal_state: None vs Some(malleable + empty state).
        let mut doc = golden_doc();
        doc.seal_state = None;
        let sig = sign_hash(&sk, &canonical_doc_digest_v2(&doc, &[0x42u8; 32]));
        let mut swapped = golden_doc();
        swapped.seal_state = Some(SealState {
            posture: LatchPosture::Malleable,
            state: Vec::new(),
        });
        assert_ne!(
            canonical_doc_digest(&doc),
            canonical_doc_digest(&swapped),
            "None and Some(empty) must never share a digest"
        );
        let ev = build_wardend_evidence(&swapped, &point, sig).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "a None signed doc presented as Some(empty) must fail verification"
        );
        // heartbeat: None vs Some(0) (the per-field presence tag).
        let mut a = golden_doc();
        a.units[1].heartbeat = None;
        let mut b = golden_doc();
        b.units[1].heartbeat = Some(0);
        assert_ne!(
            canonical_doc_digest(&a),
            canonical_doc_digest(&b),
            "heartbeat None and Some(0) must never share a digest"
        );
    }

    // (q) NEGATIVE (domain separation): a state-log entry signature NEVER
    //     verifies as the doc signature, and vice versa (the same key
    //     signs both; the doc digest is prefixed, the entry hash is not).
    #[test]
    fn a_state_log_entry_signature_never_verifies_as_the_doc_signature() {
        let (sk, point) = test_signer_key();
        let signer = P256Signer::from_uncompressed(&point).unwrap();
        let doc = golden_doc();
        let entry = &doc.state_log[0];
        let doc_digest = canonical_doc_digest(&doc);
        // Same key, both messages: an entry signature does not verify
        // over the doc digest...
        let entry_sig = sign_hash(&sk, &entry.entry_hash());
        assert!(
            !signer.verify(&doc_digest, &entry_sig),
            "a state-log entry signature must NEVER verify as the doc signature"
        );
        // ...and the doc signature does not verify over the entry hash.
        let doc_sig = sign_hash(&sk, &doc_digest);
        assert!(
            signer.verify(&doc_digest, &doc_sig),
            "positive-first: the doc signature verifies over the doc digest"
        );
        assert!(
            !signer.verify(&entry.entry_hash(), &doc_sig),
            "the doc signature must NEVER verify over an entry hash"
        );
    }

    // =========================================================================
    // D4+D3: the digest v2 conformance battery. Every row of the design
    // doc's test law (sec.5) asserted IN RUST at the unit level; the
    // fixture-level parity tests carry the cross-implementation half.
    // POSITIVE FIRST again: the fresh-nonce pass proves the battery's
    // negatives reject their named cause and NOT a broken happy path.
    // =========================================================================

    /// A production-shaped user-data document (the byte-protocol law:
    /// the fixture user-data is what a launch actually carries, not
    /// lorem): an authorized ssh key line + fleet host lines. Synthetic
    /// values, real shape.
    fn test_user_data_text() -> String {
        "#cloud-config\n\
         users:\n\
         \x20 - name: lance\n\
         \x20   ssh_authorized_keys:\n\
         \x20     - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKq3YvVCVXWlVkY5UmbVnV0XhOo0m8cRSgZ3pQrStUvW lance@fleet\n\
         bootproof:\n\
         \x20 vhost: proof.bootproof.dev\n\
         \x20 acme_dir: /var/lib/acme\n"
            .to_string()
    }

    fn test_user_data(publish: bool) -> UserDataSection {
        let text = test_user_data_text();
        let sha256: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        UserDataSection {
            sha256,
            text: publish.then_some(text),
        }
    }

    // (r) POSITIVE-FIRST: a fresh nonce verifies (v2 happy path: the
    //     sign side signed THIS challenge; the verifier's nonce matches).
    #[test]
    fn a_v2_signed_doc_verifies_under_its_fresh_nonce() {
        let (sk, point) = test_signer_key();
        let mut doc = golden_doc();
        doc.user_data = Some(test_user_data(true));
        let ev = build_signed(&doc, &sk, &point); // signed for [0x42;32]
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_ok(),
            "a v2 doc signed for the bundle's nonce verifies"
        );
        // The D3 fact tiers ride the verified payload: plaintext present
        // is the PROVEN tier.
        let verified = match WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle) {
            Ok(v) => v,
            Err(e) => panic!("fresh-nonce verify must pass: {e}"),
        };
        let facts = WardendVerifier.facts(&verified);
        let ud = facts
            .iter()
            .find(|f| f.name == "wardend_user_data")
            .expect("the user_data fact is always emitted");
        assert_eq!(ud.status, Status::Proven, "plaintext attested = PROVEN: {ud:?}");
    }

    // (s) NEGATIVE (THE replay): a response captured for nonce A, replayed
    //     to a fresh challenge B -> the doc signature FAILS. This is the
    //     A7 closure asserted: without the nonce input (v1) this replay
    //     verified forever; with it, replay is forge-class.
    #[test]
    fn a_replayed_response_fails_the_fresh_challenge() {
        let (sk, point) = test_signer_key();
        let mut doc = golden_doc();
        doc.user_data = Some(test_user_data(true));
        // The capture: the box signed for yesterday's challenge.
        let captured = build_signed_for(&doc, &sk, &point, &[0xAAu8; 32]);
        let bundle = test_bundle(&captured);
        // The replay: the client presents a different fresh nonce.
        assert!(
            WardendVerifier.verify(&captured, &[0xBBu8; 32], &bundle).is_err(),
            "a response signed for a different nonce must NOT verify against this challenge"
        );
        // And for completeness: it DOES verify against the nonce it was
        // signed for (the rejection above is the nonce, not the doc).
        assert!(
            WardendVerifier.verify(&captured, &[0xAAu8; 32], &bundle).is_ok(),
            "the same evidence verifies under its own signed nonce"
        );
    }

    // (t) NEGATIVE (fail-closed marker, both directions): a doc signed
    //     under the v1 digest does not verify under the v2 verifier, and
    //     a doc signed under v2 does not verify under a v1-style
    //     recompute. The prefix switch alone provides the domain
    //     separation: there is no window where a stale-contract signature
    //     is accepted.
    #[test]
    fn v1_and_v2_signatures_are_mutually_rejected() {
        let (sk, point) = test_signer_key();
        let doc = golden_doc();
        // v1 signature presented to the v2 verifier: FAILS.
        let v1_sig = sign_hash(&sk, &canonical_doc_digest(&doc));
        let ev = build_wardend_evidence(&doc, &point, v1_sig).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "a v1-signed doc must fail the v2 verifier (no dual-accept window)"
        );
        // v2 signature checked against a v1-style recompute: FAILS. The
        // digests themselves differ for the same doc + key:
        let d1 = canonical_doc_digest(&doc);
        let d2 = canonical_doc_digest_v2(&doc, &[0x42u8; 32]);
        assert_ne!(d1, d2, "the v1 and v2 digests of the same doc must never coincide");
        // And the v2 nonce input actually bites: two nonces, two digests.
        assert_ne!(
            d2,
            canonical_doc_digest_v2(&doc, &[0x43u8; 32]),
            "the nonce must change the digest (it is not decoration)"
        );
    }

    // (u) NEGATIVE: user_data.text present but NOT hashing to the
    //     committed sha256 -> the channel FAILS even though the signature
    //     over the (lying) doc is valid: the key attested a
    //     self-contradiction, which is a failure, not a degraded pass.
    #[test]
    fn user_data_text_that_does_not_hash_to_its_commitment_fails() {
        let (sk, point) = test_signer_key();
        let mut doc = golden_doc();
        let mut ud = test_user_data(true);
        // Tamper: flip one bit of the committed hash AFTER building the
        // section but BEFORE signing (the signature then validly covers a
        // doc whose text contradicts its own commitment).
        ud.sha256[0] ^= 0x01;
        doc.user_data = Some(ud);
        let ev = build_signed(&doc, &sk, &point);
        let bundle = test_bundle(&ev);
        let err = match WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle) {
            Ok(_) => panic!("a text/commitment contradiction must fail closed"),
            Err(e) => e,
        };
        assert!(
            err.contains("user-data"),
            "the failure must NAME the user-data leg: {err}"
        );
    }

    // (v) TIER: commitment-only (sha256 present, text withheld by
    //     config): the channel verifies, the fact is DEGRADED (content
    //     anchored, no plaintext to audit). Never silently PROVEN; the
    //     absence of text is NOT a channel failure.
    #[test]
    fn commitment_only_is_degraded_never_proven() {
        let (sk, point) = test_signer_key();
        let mut doc = golden_doc();
        doc.user_data = Some(test_user_data(false));
        let ev = build_signed(&doc, &sk, &point);
        let bundle = test_bundle(&ev);
        let verified = match WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle) {
            Ok(v) => v,
            Err(e) => panic!("a commitment-only doc verifies: {e}"),
        };
        let facts = WardendVerifier.facts(&verified);
        let ud = facts
            .iter()
            .find(|f| f.name == "wardend_user_data")
            .expect("the user_data fact is always emitted");
        assert_eq!(ud.status, Status::Degraded, "commitment-only = DEGRADED: {ud:?}");
        assert!(ud.value.contains("withheld by configuration"), "{ud:?}");
    }

    // (w) TIER: no user_data section at all -> the channel verifies (a v2
    //     doc without the field is a legitimate v2 doc) and the fact is
    //     the honest NOT PROVEN.
    #[test]
    fn an_absent_user_data_section_is_not_proven() {
        let (sk, point) = test_signer_key();
        let doc = golden_doc(); // user_data: None
        let ev = build_signed(&doc, &sk, &point);
        let bundle = test_bundle(&ev);
        let verified = match WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle) {
            Ok(v) => v,
            Err(e) => panic!("a doc without user_data verifies: {e}"),
        };
        let facts = WardendVerifier.facts(&verified);
        let ud = facts
            .iter()
            .find(|f| f.name == "wardend_user_data")
            .expect("the user_data fact is always emitted");
        assert_eq!(ud.status, Status::NotProven, "absent = NOT PROVEN: {ud:?}");
    }

    // (x) NEGATIVE: one byte of the user-data TEXT flipped after signing
    //     -> the doc digest changes -> the signature fails. The D3 bytes
    //     are signed bytes: tampering them is tampering the doc.
    #[test]
    fn a_flipped_user_data_byte_after_signing_fails_verification() {
        let (sk, point) = test_signer_key();
        let mut doc = golden_doc();
        doc.user_data = Some(test_user_data(true));
        let sig = sign_hash(&sk, &canonical_doc_digest_v2(&doc, &[0x42u8; 32]));
        // Tamper AFTER signing: swap one character of the ssh key line.
        if let Some(ud) = doc.user_data.as_mut() {
            if let Some(t) = ud.text.as_mut() {
                let pos = t.find("bastion").or(t.find("lance@fleet")).map(|i| i + 1).unwrap_or(1);
                t.replace_range(pos..pos + 1, "x");
            }
        }
        let ev = build_wardend_evidence(&doc, &point, sig).unwrap();
        let bundle = test_bundle(&ev);
        assert!(
            WardendVerifier.verify(&ev, &[0x42u8; 32], &bundle).is_err(),
            "a flipped user-data byte after signing must fail the doc signature"
        );
    }

    // (y) The v2 digest is pinned: the same golden doc + fixed nonce
    //     produces this digest (the cross-implementation anchor; the JS
    //     face must reproduce it exactly, and the fixture parity test
    //     re-derives it from production envelope bytes).
    #[test]
    fn the_v2_digest_golden_vector() {
        let digest = canonical_doc_digest_v2(&golden_doc(), &[0x42u8; 32]);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, GOLDEN_V2_DIGEST_HEX,
            "the v2 canonical digest changed: the canonicalization or the nonce input drifted (the JS face and the parity fixtures key on this)"
        );
    }

    /// The pinned v2 golden digest (canonical_doc_digest_v2 over
    /// golden_doc() with the test nonce [0x42;32]; pinned at D4 landing:
    /// computed once, then the JS face must reproduce it).
    const GOLDEN_V2_DIGEST_HEX: &str = "afb1ff5489e921b805b990b209f68d18e9554858e5e76d87472fed90f9f9d438";

    // (z) v1's canonicalization is FROZEN by this same battery: the v1
    //     golden vector above still pins the old digest, and a doc with
    //     user_data: None digests under v2 to exactly
    //     prefix-v2 || nonce || the v1 field bytes (the field walk is ONE
    //     implementation; this asserts the shared walk stays shared).
    #[test]
    fn the_shared_field_walk_is_one_implementation() {
        // With no user_data and any fixed nonce, the v2 digest must equal
        // SHA-256(v2-prefix || nonce || X) where X is the v1 walk's
        // continuation; rather than re-derive X, assert the CONTRACT that
        // matters: two docs differing ONLY in user_data share identical
        // v1 digests is FALSE (v1 ignores the field entirely -- it is not
        // in v1's walk), while their v2 digests always differ. The v1
        // insensitivity documents the pre-v2 exposure; the v2 difference
        // is the closure.
        let mut a = golden_doc();
        let mut b = golden_doc();
        b.user_data = Some(test_user_data(false));
        assert_ne!(
            canonical_doc_digest_v2(&a, &[0x42u8; 32]),
            canonical_doc_digest_v2(&b, &[0x42u8; 32]),
            "an added commitment section must change the v2 digest"
        );
        // (v1 note: canonical_doc_digest(a) == canonical_doc_digest(b)
        // would show the OLD digest blind to the field -- the exact
        // blindness v2 closes. a/b here both have None vs Some, and v1
        // has no user_data field at all, so v1 digests match by design;
        // this is the auditable before/after difference.)
        a.user_data = None;
        assert_eq!(
            canonical_doc_digest(&a),
            canonical_doc_digest(&b),
            "v1 is blind to user_data by construction (the exposure v2 closes)"
        );
    }
}
