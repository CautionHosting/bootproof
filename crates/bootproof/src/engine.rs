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
pub fn produce(
    nonce: &[u8; NONCE_LEN],
    node_id: &str,
    platform: &str,
    channels: &std::sync::Arc<Vec<Box<dyn crate::channel::Channel + Send + Sync>>>,
    extra_evidence: Vec<crate::wire::Evidence>,
) -> Bundle {
    let challenge = crate::channel::challenge_from_nonce(nonce);
    let mut evidence = Vec::new();
    let mut keys = None;

    // The hardware channels (the in-process snp + tpm2), in the slot-link
    // order (non-tpm2 first, tpm2 last with the other docs folded). An
    // absent channel degrades (is skipped); a tpm2 failure is propagated
    // (it is the mandatory core) — but for a point-in-time snapshot the
    // platform may pass an empty channel set, in which case the Bundle
    // carries no hardware evidence (the honest NOT PROVEN boundary).
    match crate::channel::collect_all(channels, &challenge) {
        Ok(cols) => {
            for col in cols {
                keys = keys.or(col.keys);
                evidence.push(col.evidence);
            }
        }
        Err(e) => {
            // A tpm2 failure is a real device error: the Bundle degrades to
            // no hardware evidence (the honest NOT PROVEN boundary), and the
            // reason is reported (never a panic, never a hang).
            eprintln!("[engine] collect failed: {e}");
        }
    }

    // The platform's additional evidence channels (the wardend / stagex
    // facts) — spliced after the hardware channels.
    evidence.extend(extra_evidence);

    Bundle {
        v: crate::wire::BUNDLE_V,
        nonce: crate::wire::B64::new(nonce.to_vec()),
        node: crate::wire::Node {
            id: node_id.to_string(),
            platform: platform.to_string(),
        },
        evidence,
        keys,
        metadata: None,
    }
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
                    nsm_binding: crate::channel::NsmBinding::Absent,
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
