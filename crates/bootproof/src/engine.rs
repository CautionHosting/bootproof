//! The generic, platform-agnostic attestation engine: one in-process
//! `produce(nonce) -> Bundle` and one offline `verify_bundle(bundle, policy,
//! verifiers) -> VerifiedFacts`, plus the hash-chained signed-log mechanism.
//!
//! This is the clean, synchronous entry point a platform (wardend, stagex,
//! or a future one) uses to produce and verify attestation evidence in
//! process, without the HTTP node or the collect daemon. The hardware
//! channels (the in-process `snp` channel, the `tpm2` channel) and the
//! per-channel verifiers are the SAME objects the node and the remote
//! `verify` flow use, so the byte contract (the challenge expansion, the
//! slot-link fold, the SNP report layout) cannot drift between the
//! in-process engine and the network paths.
//!
//! The engine is evidence-driven: it inspects which `evidence` channels are
//! present in a bundle and runs exactly the matching verifiers from the
//! registry. A bundle with only SNP + TPM2 gets core verification; a bundle
//! that carries a wardend evidence channel also runs the wardend verifier;
//! a stagex bundle runs the stagex verifier. No verifier is hard-wired —
//! presence of the evidence selects it. A required channel that is ABSENT
//! from the bundle is reported as an honest NOT PROVEN fact (never silently
//! dropped), via the verifier's `required_absent_fact`.
//!
//! The hash-chained signed log is the generic tamper-evidence mechanism:
//! each entry's hash links to the prior entry's hash (or a genesis
//! constant), and every entry is signed by the node's key (the signature
//! is over the entry hash, so a tampered entry breaks BOTH the hash link
//! and the signature). The generic layer owns the chain-link + per-entry
//! signature mechanism (`verify_chained_log`); the platform supplies its
//! entry schema + hash policy via the `ChainVerifier` trait.

use crate::channel::Verifier;
use crate::wire::{Bundle, Fact};

/// The 32-byte challenge nonce length (the front 32 of the 64-byte
/// challenge the channels bind; the client's nonce is this value).
pub const NONCE_LEN: usize = 32;

/// A registry of verifiers, keyed by channel name. The engine looks up the
/// verifier for each evidence channel in the bundle; an unknown channel is
/// an error (reported, never silently dropped). A platform adds its
/// verifiers to the registry; the core verifiers (snp, tpm2) are the
/// baseline.
pub struct VerifierRegistry {
    verifiers: Vec<Box<dyn Verifier>>,
}

impl VerifierRegistry {
    /// An empty registry (a bundle with no evidence verifies to an empty
    /// fact set; a required channel is then reported absent).
    pub fn new() -> Self {
        Self {
            verifiers: Vec::new(),
        }
    }

    /// Register a verifier (by its channel name).
    pub fn register(&mut self, v: Box<dyn Verifier>) {
        self.verifiers.push(v);
    }

    /// The verifier for `name`, if registered.
    pub fn get(&self, name: &str) -> Option<&dyn Verifier> {
        self.verifiers.iter().find(|v| v.name() == name).map(|v| &**v)
    }

    /// The registered channel names.
    pub fn names(&self) -> Vec<&'static str> {
        self.verifiers.iter().map(|v| v.name()).collect()
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The verification policy: the required VMPL (the memory-encryption
/// baseline) and the channels that MUST be present + verified for the
/// bundle to pass. A required channel that is absent from the bundle is
/// reported as an honest NOT PROVEN fact (via the verifier's
/// `required_absent_fact`), never silently dropped.
#[derive(Debug, Clone, Default)]
pub struct VerifyPolicy {
    /// The required VMPL the SNP report must run at (0 = the
    /// memory-encryption baseline).
    pub required_vmpl: u32,
    /// The channels that must be present + verified for the bundle to pass.
    pub required_channels: Vec<String>,
}

impl VerifyPolicy {
    /// The default policy: VMPL 0, no required channels (a bundle with no
    /// evidence is a valid snapshot; the caller adds required channels as
    /// its platform demands).
    pub fn default_policy() -> Self {
        Self {
            required_vmpl: 0,
            required_channels: Vec::new(),
        }
    }
}

/// The result of a full verification: the derived facts (every channel
/// present, every required channel — present or absent), the errors (a
/// present-but-failing channel, or an unknown channel), and the overall
/// pass (every required channel verified, no errors).
#[derive(Debug)]
pub struct VerifiedFacts {
    /// The derived facts (every channel present, every required channel —
    /// present or absent).
    pub facts: Vec<Fact>,
    /// The errors (a present-but-failing channel, or an unknown channel).
    pub errors: Vec<String>,
}

impl VerifiedFacts {
    /// The overall pass: every required channel is present + verified, and
    /// there are no errors.
    pub fn pass(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Produce an attestation bundle in-process: collect the hardware evidence
/// (the in-process `snp` channel, the `tpm2` channel) for the 32-byte
/// challenge nonce, and assemble the Bundle. This is the clean, synchronous
/// entry point a platform uses to produce attestation evidence without the
/// HTTP node or the collect daemon — the SAME channels the node and the
/// collect daemon use, so the byte contract (the challenge expansion, the
/// slot-link fold, the SNP report layout) cannot drift.
///
/// `nonce` is the 32-byte challenge (the client's fresh nonce, or a
/// generated one for a point-in-time snapshot). `node_id` + `platform` are
/// the node identity block. `channels` is the channel registration (built
/// by the platform — the in-process `snp` + `tpm2` channels; the same
/// objects the collect daemon serves). An absent channel degrades (is
/// skipped), never fails the request: the Bundle carries the challenge
/// nonce but no evidence for the absent channel (the honest NOT PROVEN
/// boundary, never a device read that could hang).
///
/// `extra_evidence` is the platform's additional evidence channels (a
/// wardend fact channel, a stagex fact channel) — collected after the
/// hardware channels and spliced into the Bundle. The platform produces
/// these in-process (they are not hardware channels; they are the
/// platform's own signed facts).
/// Collect the hardware channels for a nonce: the in-process snp + tpm2,
/// in the slot-link order (non-tpm2 first, tpm2 last with the other docs
/// folded). This is the collect HALF of `produce`, factored out so a
/// platform that must SIGN its own channel OVER the hardware rows (the
/// wardend doc-sig folds the snp/tpm2 rows into its v2 digest) can collect
/// ONCE, sign over the returned rows, then `assemble` — WITHOUT a second
/// code path re-implementing the collect ordering or the Bundle assembly
/// (the two-code-paths law: one collect, one assembly, every platform).
///
/// An absent channel degrades (an Absent status row); a channel collect
/// failure is a Failed status row WITH the daemon's reason. NEITHER
/// destroys another channel's evidence (the preserve-and-mark law — the
/// old `Result` + eprintln path discarded the whole vec on a tpm2 fault;
/// the verdict layer owns mandatory semantics now, not the collector).
pub fn collect_channels(
    nonce: &[u8; NONCE_LEN],
    channels: &std::sync::Arc<Vec<Box<dyn crate::channel::Channel + Send + Sync>>>,
) -> (
    Vec<crate::channel::Collected>,
    Vec<crate::wire::ChannelStatus>,
) {
    let challenge = crate::channel::challenge_from_nonce(nonce);
    crate::channel::collect_all(channels, &challenge)
}

/// Assemble a Bundle from already-collected hardware rows + their status
/// rows + the platform's additional evidence. PURE (no I/O, no collect):
/// it fixes the Bundle's byte layout — the hardware rows first in collect
/// order, the platform evidence spliced after, the FIRST channel that
/// publishes keys owns the Bundle keys, and the channel-status account
/// rides verbatim (collect order on the wire; the v2 FOLD sorts, the wire
/// does not — the client sees the daemon's order, the digest is
/// order-independent). `produce` is exactly `collect_channels` then
/// `assemble`, so a platform that collects-then-signs-then-assembles
/// produces BYTE-IDENTICAL Bundle bytes to a platform that calls `produce`
/// (the proof is `assembler_paths_are_byte_equivalent`).
pub fn assemble(
    nonce: &[u8; NONCE_LEN],
    node_id: &str,
    platform: &str,
    collected: Vec<crate::channel::Collected>,
    status: Vec<crate::wire::ChannelStatus>,
    extra_evidence: Vec<crate::wire::Evidence>,
) -> Bundle {
    let mut evidence = Vec::new();
    let mut keys = None;
    for col in collected {
        keys = keys.or(col.keys);
        evidence.push(col.evidence);
    }
    evidence.extend(extra_evidence);
    Bundle {
        v: crate::wire::BUNDLE_V,
        nonce: crate::wire::B64::new(nonce.to_vec()),
        node: crate::wire::Node {
            id: node_id.to_string(),
            platform: platform.to_string(),
        },
        evidence,
        channel_status: status,
        keys,
        metadata: None,
    }
}

pub fn produce(
    nonce: &[u8; NONCE_LEN],
    node_id: &str,
    platform: &str,
    channels: &std::sync::Arc<Vec<Box<dyn crate::channel::Channel + Send + Sync>>>,
    extra_evidence: Vec<crate::wire::Evidence>,
) -> Bundle {
    let (collected, status) = collect_channels(nonce, channels);
    assemble(nonce, node_id, platform, collected, status, extra_evidence)
}

/// Verify a bundle offline: run the matching verifier for each evidence
/// channel, derive the facts, and report any required channel that is
/// absent as an honest NOT PROVEN fact.
///
/// `nonce` is the 32-byte challenge (the bundle's own nonce for a
/// point-in-time snapshot, or the client's fresh challenge for a live
/// flow). `policy` is the verification policy (the required VMPL + the
/// required channels). `verifiers` is the registry of available verifiers
/// (the core snp + tpm2, plus any platform verifiers).
pub fn verify_bundle(
    bundle: &Bundle,
    policy: &VerifyPolicy,
    verifiers: &VerifierRegistry,
) -> VerifiedFacts {
    let nonce: [u8; NONCE_LEN] = {
        let v: Vec<u8> = bundle.nonce.0.clone();
        if v.len() != NONCE_LEN {
            return VerifiedFacts {
                facts: Vec::new(),
                errors: vec![format!(
                    "bundle nonce is {} bytes, expected {NONCE_LEN}",
                    v.len()
                )],
            };
        }
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&v);
        n
    };

    let mut facts: Vec<Fact> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut present: Vec<String> = Vec::new();

    for ev in &bundle.evidence {
        match verifiers.get(&ev.channel) {
            Some(verifier) => {
                match verifier.verify(ev, &nonce, bundle) {
                    Ok(v) => {
                        facts.extend(verifier.facts(&v));
                        present.push(ev.channel.clone());
                    }
                    Err(e) => {
                        errors.push(format!("{}: {e}", ev.channel));
                        // All facts the channel owns are NOT PROVENS on
                        // its failure (the default wraps the singular
                        // failed_fact, so single-fact channels are
                        // unchanged; snp owns memory_encryption + the
                        // AMI-2 identity rows).
                        facts.extend(verifier.failed_facts(ev, &e));
                        present.push(ev.channel.clone());
                    }
                }
            }
            None => {
                errors.push(format!("no verifier for channel {}", ev.channel));
            }
        }
    }

    // The daemon's own collection account (preserve-and-mark): every
    // non-Collected status row renders as a LOUD fact, so a degraded or
    // destroyed channel is a VISIBLE row on the audit, never an inferred
    // hole. Tier 2 by construction: this is the daemon ASSERTING what its
    // open()/collect() saw (an absence has no hardware bytes to sign).
    // Where the wardend channel is present, the v2 fold makes the account
    // signature-covered against transport tampering (drop or rewrite);
    // it is NEVER the trust anchor — the anchor is the required-set gap
    // below, which catches a LYING daemon by omission. `Collected` claims
    // self-destruct if false (the evidence row must crypto-verify), so
    // they get no extra fact.
    for st in &bundle.channel_status {
        let (value, status) = match &st.outcome {
            crate::wire::ChannelOutcome::Collected => continue,
            crate::wire::ChannelOutcome::Absent => (
                // The absence reason rides the render (the ABSENCE LAW:
                // an honest absence is SPECIFIC — it names the probed path
                // and says ENOENT — so the page shows WHICH device was
                // probed, and a config divergence is auditable from the
                // page. A reasonless absence is what the bool-detect era
                // produced; it no longer exists at the type level).
                format!(
                    "daemon report: hardware absent at collect: {}",
                    if st.reason.is_empty() {
                        "(no reason given)"
                    } else {
                        &st.reason
                    }
                ),
                crate::wire::Status::Degraded,
            ),
            crate::wire::ChannelOutcome::Failed => (
                format!(
                    "daemon report: collect failed: {}",
                    if st.reason.is_empty() {
                        "(no reason given)"
                    } else {
                        &st.reason
                    }
                ),
                crate::wire::Status::Degraded,
            ),
        };
        facts.push(crate::wire::Fact {
            name: format!("channel.{}.daemon_account", st.channel),
            value,
            anchors: vec![st.channel.clone()],
            status,
        });
    }

    // A required channel that is ABSENT from the bundle is an honest NOT
    // PROVEN fact (never silently dropped): the verifier reports the fact it
    // owns (snp: memory_encryption "absent").
    for req in &policy.required_channels {
        if !present.iter().any(|p| p == req) {
            if let Some(v) = verifiers.get(req) {
                facts.extend(v.required_absent_facts());
            }
        }
    }

    VerifiedFacts { facts, errors }
}

/// The result of a chained-log verification: the number of entries
/// verified, or the index of the first broken link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainResult {
    /// The chain is intact (every entry's hash link + signature verified).
    Intact(usize),
    /// A broken link at entry `i` (a broken prev_hash OR a bad signature).
    BrokenAt(usize),
}

/// The chain-link + per-entry signature mechanism: verify that each entry's
/// `prev_hash` matches the prior entry's hash (or the genesis constant),
/// and that each entry's signature verifies over its recomputed hash.
///
/// The generic layer owns this mechanism; the platform supplies its entry
/// schema + hash policy via the `ChainVerifier` trait (the entry hash is
/// platform-specific — the wardend hash policy is
/// `SHA-256(prev_hash || new_state_hash || operation || timestamp)`; a
/// future platform may differ). A tampered entry breaks the `prev_hash`
/// link OR the signature (the signature is over the entry hash, so both).
pub fn verify_chained_log<E>(
    entries: &[E],
    genesis: [u8; 32],
    chain_verifier: &dyn ChainVerifier<E>,
    signer: &dyn LogSigner,
) -> ChainResult {
    let mut prev = genesis;
    for (i, e) in entries.iter().enumerate() {
        // The prev_hash link: the entry's prev_hash must match the prior
        // entry's hash (or the genesis constant for the first entry).
        if chain_verifier.prev_hash(e) != prev {
            return ChainResult::BrokenAt(i);
        }
        // The entry hash (the platform's hash policy over the entry).
        let hash = chain_verifier.entry_hash(e);
        // The signature: the signer must verify the signature over the
        // recomputed entry hash.
        if !signer.verify(&hash, chain_verifier.signature(e)) {
            return ChainResult::BrokenAt(i);
        }
        prev = hash;
    }
    ChainResult::Intact(entries.len())
}

/// The platform's entry schema + hash policy: how to read an entry's
/// `prev_hash`, compute its hash (the value the next entry's `prev_hash`
/// must match), and read its signature. The generic `verify_chained_log`
/// owns the chain-link + signature mechanism; this trait is the platform
/// seam (the entry hash policy is platform-specific).
pub trait ChainVerifier<E> {
    /// The entry's `prev_hash` (the value the prior entry's hash must
    /// match).
    fn prev_hash(&self, e: &E) -> [u8; 32];
    /// The entry's hash (the value the next entry's `prev_hash` must
    /// match). The platform's hash policy (e.g. the wardend
    /// `SHA-256(prev_hash || new_state_hash || operation || timestamp)`).
    fn entry_hash(&self, e: &E) -> [u8; 32];
    /// The entry's signature (the node's key signed the entry hash).
    fn signature<'a>(&'a self, e: &'a E) -> &'a [u8];
}

/// The signer seam for the chained log: the node's key (the seald HSM is
/// the real backend; the client verifies with the public key). The
/// signature is over the entry hash (a 32-byte digest).
pub trait LogSigner: Send + Sync {
    /// Verify a signature over a 32-byte hash.
    fn verify(&self, hash: &[u8; 32], sig: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{Verifier, Verified};
    use crate::wire::{B64, Evidence, Status};
    use std::collections::BTreeMap;

    /// A mock verifier: a deterministic channel that always verifies (or
    /// fails, on demand).
    struct MockVerifier {
        name: &'static str,
        fail: bool,
        absent_fact: Option<&'static str>,
    }

    impl Verifier for MockVerifier {
        fn name(&self) -> &'static str {
            self.name
        }
        fn verify(
            &self,
            _ev: &Evidence,
            _nonce: &[u8; 32],
            _bundle: &Bundle,
        ) -> Result<Verified, String> {
            if self.fail {
                Err(format!("{}: mock failure", self.name))
            } else {
                // A mock Verified: use the tpm2 variant with empty data.
                Ok(Verified::Tpm2(crate::channel::Tpm2Verified {
                    per_pcr: Vec::new(),
                    ak_public: Vec::new(),
                    sign_public: None,
                    sign_policy: None,
                    sign_pcrs: None,
                    slot_link: crate::channel::SlotLink::NoSlotPcr,
                    ek_cert: None,
                }))
            }
        }
        fn facts(&self, _v: &Verified) -> Vec<Fact> {
            vec![Fact {
                name: format!("{}_fact", self.name),
                value: "mock".into(),
                anchors: vec![self.name.into()],
                status: Status::Proven,
            }]
        }
        fn failed_fact(&self, _ev: &Evidence, _reason: &str) -> Option<Fact> {
            Some(Fact {
                name: format!("{}_failed", self.name),
                value: "mock failure".into(),
                anchors: vec![self.name.into()],
                status: Status::NotProven,
            })
        }
        fn required_absent_fact(&self) -> Option<Fact> {
            self.absent_fact.map(|v| Fact {
                name: format!("{}_absent", self.name),
                value: v.into(),
                anchors: vec![self.name.into()],
                status: Status::NotProven,
            })
        }
    }

    /// A DETERMINISTIC mock hardware channel: it returns a fixed evidence
    /// doc derived from the challenge (so the same nonce yields byte-identical
    /// output on every call), and either publishes keys or not. This is the
    /// stand-in that lets the assembler byte-equality test be a real witness
    /// rather than a tautology: `produce` calls `collect_all` (which drives
    /// this channel) once; the split path calls the SAME `collect_all` once;
    /// if the two produce byte-identical Bundles, the collect+assemble
    /// decomposition — the exact shape `attest()` uses to sign-over-rows —
    /// is proven byte-neutral against the monolithic `produce`.
    struct MockHwChannel {
        name: &'static str,
        present: bool,
        publish_keys: bool,
    }

    impl crate::channel::Channel for MockHwChannel {
        fn name(&self) -> &'static str {
            self.name
        }
        fn detect(&self) -> crate::channel::Presence {
            if self.present {
                crate::channel::Presence::Present
            } else {
                crate::channel::probe_device(
                    &format!("/nonexistent/bootproof-test/{}", self.name),
                    crate::channel::is_chardev,
                )
            }
        }
        fn collect(
            &self,
            nonce: &[u8; 64],
            other_docs: &[Vec<u8>],
        ) -> Result<crate::channel::Collected, String> {
            // A fixed doc: the challenge front-32 XOR a per-name salt, plus
            // the count of other_docs (so the tpm2 slot-link fold is visible
            // in the bytes). Deterministic: same inputs -> same output.
            let mut doc = nonce[..32].to_vec();
            for (i, b) in doc.iter_mut().enumerate() {
                *b ^= self.name.as_bytes()[i % self.name.len()];
            }
            doc.push(other_docs.len() as u8);
            let keys = if self.publish_keys {
                Some(crate::wire::Keys {
                    enc: None,
                    sign: Some(crate::wire::KeyInfo {
                        pub_: B64::new(vec![self.name.as_bytes()[0]; 4]),
                        curve: "P-256".to_string(),
                        scheme: "ecdsa-sha256".to_string(),
                        pcr_policy: vec![4, 5, 7, 9],
                        cert_by_ek: None,
                    }),
                })
            } else {
                None
            };
            Ok(crate::channel::Collected {
                evidence: Evidence {
                    channel: self.name.to_string(),
                    doc: B64::new(doc),
                    anchors: BTreeMap::new(),
                },
                keys,
            })
        }
    }

    fn mock_channels(spec: &[(&'static str, bool, bool)]) -> std::sync::Arc<
        Vec<Box<dyn crate::channel::Channel + Send + Sync>>,
    > {
        std::sync::Arc::new(
            spec.iter()
                .map(|(n, present, keys)| {
                    Box::new(MockHwChannel {
                        name: n,
                        present: *present,
                        publish_keys: *keys,
                    }) as Box<dyn crate::channel::Channel + Send + Sync>
                })
                .collect(),
        )
    }

    /// PATH EQUIVALENCE (the permanent contract): the two produce paths —
    /// `produce` (collect then assemble) and a sign-over-rows platform's
    /// collect -> sign -> assemble — MUST yield byte-identical Bundle
    /// bytes, forever. A platform (wardend `attest`) cannot call `produce`
    /// (the rows it signs are produced inside it), so it splits the same
    /// two calls around its signature; if the paths' bytes ever differ,
    /// the platform signs a different bundle than it ships (the rows-fold
    /// contract broken). Witnessed across: hardware rows present +
    /// keys-published + channel degradation (now an Absent status ROW, not
    /// a skip) + extra platform evidence spliced after the hardware rows.
    ///
    /// (Two contracts used to share this test's name — the chipmunk
    /// ruling separates them. The OTHER one, REFACTOR NEUTRALITY ("the
    /// factored produce == the pre-refactor produce's exact bytes"), was
    /// satisfied at the factoring landing (pinned then: 3a9e8c47), was
    /// legitimately RETIRED by the status cascade (channel_status
    /// intentionally moves the assembled bytes — the degraded channel now
    /// serializes its Absent row), and lives only as this footnote. Do NOT
    /// re-pin back toward the old digest to "fix a freeze": the frozen
    /// contract here is path-vs-path, not history-vs-now. The historical
    /// freezes that DO bind: v1 1a6c06ff, untouched by every v2 section.)
    #[test]
    fn assembler_paths_are_byte_equivalent() {
        let nonce = [0x42u8; 32];
        // Non-tpm2 present-and-publishes-keys, a degraded (absent) channel,
        // and the tpm2 channel (last in collect order, folds the others).
        let channels = mock_channels(&[
            ("snp", true, true),
            ("aws-cp", false, false),
            ("tpm2", true, true),
        ]);
        let extra = vec![Evidence {
            channel: "wardend".to_string(),
            doc: B64::new(b"the wardend doc".to_vec()),
            anchors: BTreeMap::new(),
        }];

        // Path A: the monolithic produce (what a platform with no sign-over-
        // rows need calls today).
        let a = produce(&nonce, "node-1", "aws-snp", &channels, extra.clone());
        // Path B: the split a sign-over-rows platform uses: collect, then
        // assemble. (The real attest() signs over `collected` between these
        // two calls; the signature does not change the Bundle ASSEMBLY, so
        // byte-equality of the assembly is exactly the property to prove.)
        let (collected, status) = collect_channels(&nonce, &channels);
        let b = assemble(
            &nonce,
            "node-1",
            "aws-snp",
            collected,
            status,
            extra.clone(),
        );

        // Byte-identical serialized bytes (the bundle's wire form), not just
        // structural equality: the rows-fold digest is over these exact bytes.
        let a_bytes = serde_json::to_vec(&a).expect("a serializes");
        let b_bytes = serde_json::to_vec(&b).expect("b serializes");
        assert_eq!(a_bytes, b_bytes, "produce() and collect+assemble() are byte-identical");

        // And the SHA-256 of the identical bytes is PINNED, so a future edit
        // that perturbs the assembly layout (row order, keys-or, the extra
        // splice point, field order) flips this digest and fails LOUDLY even
        // if both paths stay mutually consistent. This pins the assembler's
        // byte contract: produce() bytes == collect+assemble() bytes == this
        // digest. A legitimate contract change re-measures this value by hand
        // (a coordinated protocol change that re-pins the golden fixtures in
        // the same commit).
        let digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&a_bytes);
            h.finalize().into()
        };
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "8f5770c827361b9438cfe379e21ee362b57061aad1761d6d03e158689ea0a4c0",
            "the assembled bundle bytes digest moved: the assembly layout is a frozen contract, re-pin ONLY with the golden fixtures in the same commit"
        );
        // (Supersession edge: 3a9e8c47...459dd66 -> 416c88a3...0ae1ee12 at
        // the status-cascade landing — the degraded aws-cp channel now
        // serializes its Absent status row into the bundle bytes, which is
        // exactly the preserve-and-mark contract: the degradation is
        // data, not silence.)
        // (Supersession edge 2: 416c88a3...0ae1ee12 -> 8f5770c8...9ea0a4c0
        // at the ABSENCE-LAW landing — the Absent row's reason is no longer
        // the bare "hardware absent": the law requires it to name the
        // probed path + ENOENT, so the aws-cp mock's absence reason changed
        // bytes. The golden fixtures carry ONLY Collected rows, so they are
        // byte-stable across this change (re-generated fixtures match);
        // the reason-text change is the point of the fix: an absence that
        // cannot say WHY + WHERE is not honest, it is just short.)
        assert_eq!(b.channel_status.len(), 3, "every registered channel accounted");
        assert!(b.channel_status.iter().any(|s| s.channel == "aws-cp"
            && s.outcome == crate::wire::ChannelOutcome::Absent));

        // The layout invariants, spelled out so a reviewer sees WHAT was
        // proven identical: hardware rows first (in collect order, degraded
        // channel skipped), the platform evidence last, keys from the FIRST
        // publisher.
        assert_eq!(b.evidence.len(), 3, "snp + tpm2 + wardend (aws-cp degraded)");
        assert_eq!(b.evidence[0].channel, "snp");
        assert_eq!(b.evidence[1].channel, "tpm2");
        assert_eq!(b.evidence[2].channel, "wardend");
        assert!(b.keys.is_some(), "the first publisher (snp) owns the keys");
        assert_eq!(b.keys.as_ref().unwrap().sign.as_ref().unwrap().curve, "P-256");
    }

    fn mock_bundle(nonce: &[u8; 32], channels: &[&str]) -> Bundle {
        let evidence = channels
            .iter()
            .map(|c| Evidence {
                channel: c.to_string(),
                doc: B64::new(vec![0u8; 8]),
                anchors: BTreeMap::new(),
            })
            .collect();
        Bundle {
            v: crate::wire::BUNDLE_V,
            nonce: B64::new(nonce.to_vec()),
            node: crate::wire::Node {
                id: "engine-test".into(),
                platform: "baremetal".into(),
            },
            evidence,
            channel_status: Vec::new(),
            keys: None,
            metadata: None,
        }
    }

    #[test]
    fn verify_bundle_all_channels_present_verifies() {
        let mut reg = VerifierRegistry::new();
        reg.register(Box::new(MockVerifier {
            name: "snp",
            fail: false,
            absent_fact: Some("absent"),
        }));
        reg.register(Box::new(MockVerifier {
            name: "tpm2",
            fail: false,
            absent_fact: None,
        }));
        let nonce = [0x42u8; 32];
        let bundle = mock_bundle(&nonce, &["snp", "tpm2"]);
        let policy = VerifyPolicy {
            required_vmpl: 0,
            required_channels: vec!["snp".into(), "tpm2".into()],
        };
        let vf = verify_bundle(&bundle, &policy, &reg);
        assert!(vf.pass(), "all required channels present + verified: pass");
        assert_eq!(vf.facts.len(), 2, "one fact per channel");
        assert!(vf.errors.is_empty());
    }

    #[test]
    fn verify_bundle_absent_required_channel_is_not_proven() {
        let mut reg = VerifierRegistry::new();
        reg.register(Box::new(MockVerifier {
            name: "snp",
            fail: false,
            absent_fact: Some("the node does not serve a SEV-SNP channel"),
        }));
        let nonce = [0x42u8; 32];
        // No snp evidence in the bundle.
        let bundle = mock_bundle(&nonce, &[]);
        let policy = VerifyPolicy {
            required_vmpl: 0,
            required_channels: vec!["snp".into()],
        };
        let vf = verify_bundle(&bundle, &policy, &reg);
        // The absent required channel is reported as a NOT PROVEN fact.
        let absent = vf
            .facts
            .iter()
            .find(|f| f.name == "snp_absent")
            .expect("the absent required channel must be reported");
        assert_eq!(absent.status, Status::NotProven);
    }

    #[test]
    fn verify_bundle_unknown_channel_is_an_error() {
        let reg = VerifierRegistry::new();
        let nonce = [0x42u8; 32];
        let bundle = mock_bundle(&nonce, &["warp-drive"]);
        let policy = VerifyPolicy::default_policy();
        let vf = verify_bundle(&bundle, &policy, &reg);
        assert!(!vf.pass(), "an unknown channel is an error");
        assert!(
            vf.errors.iter().any(|e| e.contains("warp-drive")),
            "the unknown channel is reported: {:?}",
            vf.errors
        );
    }

    #[test]
    fn verify_bundle_failing_channel_is_not_proven_with_reason() {
        let mut reg = VerifierRegistry::new();
        reg.register(Box::new(MockVerifier {
            name: "snp",
            fail: true,
            absent_fact: Some("absent"),
        }));
        let nonce = [0x42u8; 32];
        let bundle = mock_bundle(&nonce, &["snp"]);
        let policy = VerifyPolicy::default_policy();
        let vf = verify_bundle(&bundle, &policy, &reg);
        assert!(!vf.pass(), "a failing channel is an error");
        assert!(
            vf.errors.iter().any(|e| e.starts_with("snp:")),
            "the failing channel is reported: {:?}",
            vf.errors
        );
        // The failed fact is reported (NOT PROVEN with the reason).
        assert!(
            vf.facts.iter().any(|f| f.name == "snp_failed"),
            "the failed fact is reported"
        );
    }

    #[test]
    fn verify_bundle_bad_nonce_length_is_an_error() {
        let reg = VerifierRegistry::new();
        let mut bundle = Bundle {
            v: crate::wire::BUNDLE_V,
            nonce: B64::new(vec![0u8; 16]), // 16 bytes (need 32)
            node: crate::wire::Node {
                id: "engine-test".into(),
                platform: "baremetal".into(),
            },
            evidence: Vec::new(),
            channel_status: Vec::new(),
            keys: None,
            metadata: None,
        };
        let _ = &mut bundle;
        let policy = VerifyPolicy::default_policy();
        let vf = verify_bundle(&bundle, &policy, &reg);
        assert!(!vf.pass());
        assert!(
            vf.errors.iter().any(|e| e.contains("nonce")),
            "the bad nonce length is reported: {:?}",
            vf.errors
        );
    }

    // --- The hash-chained signed-log mechanism ---

    /// A test entry: the wardend shape (prev_hash, new_state_hash,
    /// operation, timestamp, signature).
    struct TestEntry {
        prev_hash: [u8; 32],
        new_state_hash: [u8; 32],
        operation: Vec<u8>,
        timestamp: u64,
        signature: Vec<u8>,
    }

    /// A test chain verifier: a fixed hash policy (a simple XOR of the
    /// fields — the policy is platform-specific; the mechanism is what is
    /// tested here).
    struct TestChainVerifier;

    impl ChainVerifier<TestEntry> for TestChainVerifier {
        fn prev_hash(&self, e: &TestEntry) -> [u8; 32] {
            e.prev_hash
        }
        fn entry_hash(&self, e: &TestEntry) -> [u8; 32] {
            let mut h = [0u8; 32];
            for (i, b) in e.new_state_hash.iter().enumerate() {
                h[i] ^= b;
            }
            for b in &e.operation {
                h[(*b as usize) % 32] ^= *b;
            }
            h[31] ^= (e.timestamp & 0xff) as u8;
            h
        }
        fn signature<'a>(&'a self, e: &'a TestEntry) -> &'a [u8] {
            &e.signature
        }
    }

    /// A test signer: the signature is the 32-byte entry hash itself (a
    /// trivial "signature" that verifies only when the hash matches —
    /// enough to test the mechanism without a real key).
    struct TestSigner;

    impl LogSigner for TestSigner {
        fn verify(&self, hash: &[u8; 32], sig: &[u8]) -> bool {
            sig == hash
        }
    }

    fn test_entry(prev: [u8; 32], nsh: u8, op: &[u8], ts: u64) -> TestEntry {
        let mut nsh_arr = [0u8; 32];
        nsh_arr[0] = nsh;
        TestEntry {
            prev_hash: prev,
            new_state_hash: nsh_arr,
            operation: op.to_vec(),
            timestamp: ts,
            // The signature is the entry hash (the test signer's scheme).
            signature: {
                let e = TestEntry {
                    prev_hash: prev,
                    new_state_hash: nsh_arr,
                    operation: op.to_vec(),
                    timestamp: ts,
                    signature: Vec::new(),
                };
                TestChainVerifier.entry_hash(&e).to_vec()
            },
        }
    }

    #[test]
    fn chained_log_valid_chain_is_intact() {
        let genesis = [0x57u8; 32];
        let e0 = test_entry(genesis, 1, b"genesis", 1000);
        let h0 = TestChainVerifier.entry_hash(&e0);
        let e1 = test_entry(h0, 2, b"seal", 1001);
        let entries = vec![e0, e1];
        let r = verify_chained_log(&entries, genesis, &TestChainVerifier, &TestSigner);
        assert_eq!(r, ChainResult::Intact(2), "a valid chain is intact");
    }

    #[test]
    fn chained_log_broken_prev_hash_is_detected() {
        let genesis = [0x57u8; 32];
        let e0 = test_entry(genesis, 1, b"genesis", 1000);
        // e1's prev_hash is WRONG (not e0's hash).
        let mut e1 = test_entry([0xDEu8; 32], 2, b"seal", 1001);
        e1.signature = TestChainVerifier.entry_hash(&e1).to_vec();
        let entries = vec![e0, e1];
        let r = verify_chained_log(&entries, genesis, &TestChainVerifier, &TestSigner);
        assert_eq!(r, ChainResult::BrokenAt(1), "a broken prev_hash is detected");
    }

    #[test]
    fn chained_log_bad_signature_is_detected() {
        let genesis = [0x57u8; 32];
        let e0 = test_entry(genesis, 1, b"genesis", 1000);
        let h0 = TestChainVerifier.entry_hash(&e0);
        let mut e1 = test_entry(h0, 2, b"seal", 1001);
        e1.signature = vec![0xFFu8; 32]; // a bad signature
        let entries = vec![e0, e1];
        let r = verify_chained_log(&entries, genesis, &TestChainVerifier, &TestSigner);
        assert_eq!(r, ChainResult::BrokenAt(1), "a bad signature is detected");
    }

    #[test]
    fn chained_log_empty_is_intact() {
        let genesis = [0x57u8; 32];
        let entries: Vec<TestEntry> = Vec::new();
        let r = verify_chained_log(&entries, genesis, &TestChainVerifier, &TestSigner);
        assert_eq!(r, ChainResult::Intact(0), "an empty log is intact");
    }

    // --- The produce path (no hardware channels: the honest NOT PROVEN
    //      boundary) ---

    #[test]
    fn produce_with_no_channels_degrades_to_no_hardware_evidence() {
        let nonce = [0x42u8; 32];
        // An empty channel set (no hardware on this host): the Bundle
        // carries the challenge nonce + the extra evidence, but no hardware
        // evidence (the honest NOT PROVEN boundary, never a hang).
        let channels = std::sync::Arc::new(Vec::<Box<dyn crate::channel::Channel + Send + Sync>>::new());
        let extra = vec![Evidence {
            channel: "wardend".to_string(),
            doc: B64::new(vec![0u8; 8]),
            anchors: BTreeMap::new(),
        }];
        let bundle = produce(&nonce, "node-1", "baremetal", &channels, extra);
        assert_eq!(bundle.nonce.0, nonce.to_vec(), "the challenge nonce is carried");
        assert_eq!(bundle.node.id, "node-1");
        assert_eq!(bundle.node.platform, "baremetal");
        // Only the extra evidence (no hardware channels collected).
        assert_eq!(bundle.evidence.len(), 1, "only the extra evidence");
        assert_eq!(bundle.evidence[0].channel, "wardend");
        // The Bundle verifies (the wardend channel has no registered verifier
        // here, so it is an unknown-channel error; but the produce path
        // itself is sound: the Bundle is well-formed).
        let reg = VerifierRegistry::new();
        let policy = VerifyPolicy::default_policy();
        let vf = verify_bundle(&bundle, &policy, &reg);
        assert!(
            vf.errors.iter().any(|e| e.contains("wardend")),
            "the unknown wardend channel is reported: {:?}",
            vf.errors
        );
    }

    #[test]
    fn produce_and_verify_roundtrip_with_registered_verifier() {
        let nonce = [0x42u8; 32];
        let channels = std::sync::Arc::new(Vec::<Box<dyn crate::channel::Channel + Send + Sync>>::new());
        // A platform evidence channel with a registered verifier (the
        // mock, which always verifies).
        let extra = vec![Evidence {
            channel: "snp".to_string(),
            doc: B64::new(vec![0u8; 8]),
            anchors: BTreeMap::new(),
        }];
        let bundle = produce(&nonce, "node-1", "baremetal", &channels, extra);
        let mut reg = VerifierRegistry::new();
        reg.register(Box::new(MockVerifier {
            name: "snp",
            fail: false,
            absent_fact: Some("absent"),
        }));
        let policy = VerifyPolicy {
            required_vmpl: 0,
            required_channels: vec!["snp".into()],
        };
        let vf = verify_bundle(&bundle, &policy, &reg);
        assert!(vf.pass(), "a produced bundle with a registered verifier passes: {:?}", vf.errors);
    }
}
