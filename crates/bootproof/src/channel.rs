//! The lean core: one `Channel` per attestation type on the node, one
//! `Verifier` on the client. Adding a platform later (TDX, GCP, Azure) is
//! one new module implementing these two traits; the Bundle, the HTTP
//! surface, the table renderer, and pinning are untouched.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::wire::{Bundle, Evidence, Fact, Keys};

/// The honest-absence witness (the ABSENCE LAW's type-level teeth, per
/// chipmunk: "keep the honest path the only easy path"). The reason field
/// is PRIVATE and this struct lives in `channel`, so outside this module
/// an `Absent` cannot be hand-fabricated: the only constructors are
/// `honest` (accepts ENOENT-class errors, refuses everything else) and
/// `wrong_type` (metadata answered and the node type says otherwise).
/// A rogue channel that wants to render a denial as an absence has to
/// write the lie in a diff that says ENOENT when it is not.
#[derive(Debug, Clone)]
pub struct Absence {
    reason: String,
}

impl Absence {
    /// THE constructor: an absence is honest only if the stat answered
    /// ENOENT. Any other error is not an absence — `None` (the caller
    /// must render the denial, not the absence).
    pub fn honest(path: &str, e: &std::io::Error) -> Option<Self> {
        (e.kind() == std::io::ErrorKind::NotFound)
            .then(|| Self { reason: format!("{path}: not present (ENOENT)") })
    }

    /// Metadata answered and the node is not the expected device type:
    /// stat succeeded, so this is a proven absence of THE DEVICE (a
    /// regular file is not a chardev), not a denial.
    fn wrong_type(path: &str) -> Self {
        Self { reason: format!("{path}: exists but is not the expected device type") }
    }

    /// The reason the absence is honest (rides the wire in the Absent row).
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// The presence verdict of a channel probe (unification, THE ABSENCE LAW:
/// "absence requires ENOENT; any other stat errno is a denial or a lie, and
/// denials are loud"). A bool cannot carry the law: `Path::exists()` swallows
/// EVERY stat errno, so parent-traversal EACCES (the seam-rot class) rendered
/// as honest absence — the campaign's defect family inside the trait. The
/// three-cell enum makes the swallow impossible: only ENOENT maps to Absent,
/// every other errno is Denied (a LOUD Failed row, never an Absence).
#[derive(Debug, Clone)]
pub enum Presence {
    /// The device node is present (stat answered, char-device-shaped).
    Present,
    /// THE honest absence: stat answered ENOENT and nothing else. Construct
    /// it only through `probe_device` / `Absence::honest` — the reason is
    /// private so a fabricated absence is a visible, auditable lie.
    Absent(Absence),
    /// A stat denial or unclassifiable errno (EACCES on the node or on a
    /// parent traversal, ELOOP, ...): the daemon cannot prove absence, and
    /// "cannot prove absence" is NOT absence. Renders as a Failed row with
    /// the errno in the reason.
    Denied(String),
}

/// Node-type filter for `probe_device`: a character device (both
/// attestation devices — `/dev/sev-guest`, `/dev/tpm*` — are chardevs).
#[cfg(target_os = "linux")]
pub fn is_chardev(mode: u32) -> bool {
    // S_IFCHR (0o020000) set and the file-type bits say char device: the
    // classic `S_ISCHR` against the raw st_mode from MetadataExt::mode().
    mode & 0o170000 == 0o020000
}

#[cfg(not(target_os = "linux"))]
pub fn is_chardev(_mode: u32) -> bool {
    true
}

/// Metadata probe for a device node, THE ABSENCE LAW as one function
/// (unification — shared by the runtime SNP + TPM2 channels, mirrored by
/// wardend's boot-plane `device_present_at`): stat the path, classify the
/// errno. ENOENT and nothing else is Absent; every other stat errno is
/// Denied (loud). `want` filters the node type (both attestation devices
/// are char devices); path errors that are not NotFound (EACCES traversal,
/// ELOOP, ENOTDIR, ...) are Denied — they are lies about the path, not
/// absences of the device.
pub fn probe_device(path: &str, want: fn(u32) -> bool) -> Presence {
    match std::fs::metadata(path) {
        Ok(md) => {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt;
                if want(md.mode()) {
                    Presence::Present
                } else {
                    Presence::Absent(Absence::wrong_type(path))
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = want;
                Presence::Present
            }
        }
        // PermissionDenied covers EACCES on a parent traversal (the
        // seam-rot class). Everything else (ELOOP, ENOTDIR, ESTALE, ...)
        // is equally unclassifiable as absence.
        Err(e) => match Absence::honest(path, &e) {
            Some(a) => Presence::Absent(a),
            None => Presence::Denied(format!("{path}: cannot prove absence ({e})")),
        },
    }
}

/// Attest-side: a channel produces signed evidence for a challenge nonce.
pub trait Channel {
    /// Channel name: "snp" | "tpm2" | "aws-cp" | ...
    fn name(&self) -> &'static str;

    /// Is this channel available on this host? THE PRESENCE LAW (unification,
    /// chipmunk): presence is a METADATA question, access is a COLLECT-TIME
    /// question. A `detect()` that opens conflates them and renders denials
    /// as absences — a DAC/seam-rot EACCES would read as "hardware absent"
    /// on the wire, telling an auditor the device does not exist when the
    /// real fact is "present but refused". Implementations must metadata-
    /// probe (stat-class: type + errno), never open; the access verdict
    /// belongs in `collect()` as an `Err(reason)` (Failed + reason), never
    /// as Absent. THE ABSENCE LAW: absence requires ENOENT; any other stat
    /// errno is `Denied` (loud), never `Absent`.
    fn detect(&self) -> Presence;

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

/// The channel-status types are WIRE types (they ride the Bundle + the
/// collect socket), so they live in `wire`; re-exported here so the collect
/// path and every consumer names them as `channel::ChannelStatus`.
pub use crate::wire::{ChannelOutcome, ChannelStatus};

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
/// the non-tpm2 channels first (so their doc bytes are available for the
/// tpm2 slot-link fold), then the tpm2 channel LAST with `other_docs` set
/// to the non-tpm2 channels' raw doc bytes in channel-name order. The tpm2
/// channel folds those into the slot link (PCR22) before quoting, which is
/// what binds every channel to one TPM at one moment.
///
/// `channels` is the shared registration (built once by `attest::build_channels`
/// and used by both the `collect` daemon and the `attest` in-process fallback).
/// Returns the collected entries in collect order (non-tpm2 channels, then
/// tpm2) PLUS one status row per registered channel: the PRESERVE-AND-MARK
/// contract (the old signature returned `Result` and the tpm2 failure
/// propagated with `?`, which made the caller discard the WHOLE vec —
/// a valid snp row already collected was destroyed by an unrelated tpm
/// fault: collateral-discard, absence dressed as honest degradation).
/// Collection NEVER destroys evidence; the VERDICT layer (verify_bundle +
/// the browser verifier) owns mandatory semantics and decides what a
/// missing required channel means. A tpm2 failure is still LOUD — it is a
/// Failed status row, folded + transmitted — it is just no longer fatal to
/// the other channels' evidence.
pub fn collect_all(
    channels: &Arc<Vec<Box<dyn Channel + Send + Sync>>>,
    challenge: &[u8; 64],
) -> (Vec<Collected>, Vec<ChannelStatus>) {
    let mut docs: Vec<Vec<u8>> = Vec::new();
    let mut out: Vec<Collected> = Vec::new();
    let mut status: Vec<ChannelStatus> = Vec::new();
    let status_row = |channel: &str, outcome: ChannelOutcome, reason: String| ChannelStatus {
        channel: channel.to_string(),
        outcome,
        reason,
    };
    for c in channels.iter() {
        if c.name() == "tpm2" {
            continue;
        }
        match c.detect() {
            Presence::Present => match c.collect(challenge, &docs) {
                Ok(col) => {
                    docs.push(col.evidence.doc.0.clone());
                    status.push(status_row(c.name(), ChannelOutcome::Collected, String::new()));
                    out.push(col);
                }
                Err(e) => {
                    warn!(channel = c.name(), %e, "channel collect failed; degrading");
                    status.push(status_row(c.name(), ChannelOutcome::Failed, e));
                }
            },
            // Honest absence (ENOENT and nothing else): the reason names
            // the probed path, so a config divergence is auditable from
            // the page.
            Presence::Absent(a) => {
                let reason = a.reason().to_string();
                warn!(channel = c.name(), %reason, "channel absent");
                status.push(status_row(c.name(), ChannelOutcome::Absent, reason));
            }
            // "Cannot prove absence" is NOT absence: a stat denial renders
            // LOUD as Failed — never an Absent row telling the auditor the
            // device does not exist.
            Presence::Denied(reason) => {
                warn!(channel = c.name(), %reason, "presence probe denied");
                status.push(status_row(
                    c.name(),
                    ChannelOutcome::Failed,
                    format!("presence probe denied: {reason}"),
                ));
            }
        }
    }
    for c in channels.iter() {
        if c.name() != "tpm2" {
            continue;
        }
        // The mandatory channel: a failure is preserved-and-marked, never
        // propagated (the `?` here used to destroy every row collected
        // above — the collateral-discard defect). The verdict layer renders
        // the mandatory failure; the evidence layer never destroys it.
        match c.collect(challenge, &docs) {
            Ok(col) => {
                status.push(status_row(c.name(), ChannelOutcome::Collected, String::new()));
                out.push(col);
            }
            Err(e) => {
                warn!(channel = c.name(), %e, "mandatory channel collect failed");
                status.push(status_row(c.name(), ChannelOutcome::Failed, e));
            }
        }
    }
    (out, status)
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

    /// A fact this channel OWNS when it is REQUIRED by the verification
    /// policy but its evidence is ABSENT from the bundle: rendered as NOT
    /// PROVEN "absent". Honest degradation: a required channel the node
    /// does not serve is never silently dropped (the snp channel:
    /// `memory_encryption` "absent"). A channel that is not a required
    /// fact-owner returns `None`.
    fn required_absent_fact(&self) -> Option<Fact> {
        None
    }

    /// All failure-time facts this channel owns, when its evidence is
    /// present but verification failed. The default wraps the singular
    /// `failed_fact`, so every existing channel is byte-identical. A
    /// channel that owns MORE than one fact (snp: `memory_encryption`
    /// plus the AMI-2 identity rows) overrides this, so one verification
    /// failure NOT PROVENS every fact it owns -- the state the JS
    /// verifier shows on the same bundle (two verifiers, one verdict).
    fn failed_facts(&self, ev: &Evidence, reason: &str) -> Vec<Fact> {
        self.failed_fact(ev, reason).into_iter().collect()
    }

    /// All required-absent facts. The default wraps the singular
    /// `required_absent_fact`. Deliberately NOT overridden by snp: an
    /// ABSENT report has no bytes to display, so the identity rows do
    /// not exist on absence in either verifier (absence is honest
    /// silence on those rows; tampering is a present row saying NOT
    /// PROVEN -- the two states must stay distinguishable).
    fn required_absent_facts(&self) -> Vec<Fact> {
        self.required_absent_fact().into_iter().collect()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod absence_law_tests {
    //! THE ABSENCE LAW battery: ENOENT is the only honest absence; every
    //! other stat errno is a loud denial. Each cell is forged from real
    //! filesystem state (no mocks of the errno itself — the witness is
    //! the kernel's answer), in the process's own credential class.
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("bootproof-absence-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn enoent_is_the_only_honest_absence() {
        let dir = scratch("enoent");
        let missing = dir.join("sev-guest");
        match probe_device(&missing.to_string_lossy(), is_chardev) {
            Presence::Absent(a) => {
                assert!(a.reason().contains("ENOENT"), "names the errno: {}", a.reason());
                assert!(a.reason().contains("sev-guest"), "names the path: {}", a.reason());
            }
            other => panic!("ENOENT must be Absent, got {other:?}"),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn eacces_on_parent_traversal_is_denied_never_absent() {
        // The seam-rot class, forged honestly: a mode-000 parent directory
        // makes the kernel answer EACCES for the traversal. This process
        // runs WITHOUT DAC_OVERRIDE (no capabilities), so the refusal is
        // the same class a sealed daemon hits on a locked /dev tree.
        //
        // Why THIS cell is the ONLY cell (chipmunk's ruling, closed
        // unreachable-by-construction): under a METADATA probe, stat EACCES
        // arises from PARENT-TRAVERSAL denial only — a node's own mode bits
        // gate open, not stat (DAC on the node is an open-time question).
        // The EACCES-on-the-node-itself cell was reachable under the
        // RETIRED open-based detect: it is a property of the dead code. This
        // cell does not merely prove the Err arm of metadata(); it proves
        // the ONLY arm that arm can take. Caveat that keeps it honest: the
        // cell becomes reachable again the moment any production path
        // re-introduces opens-to-verify — the sensor inventory's remaining
        // access-based rows are exactly what would resurrect it, so the
        // inventory keeps this property checkable.
        let dir = scratch("trav");
        let locked = dir.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let target = locked.join("tpm0");
        match probe_device(&target.to_string_lossy(), is_chardev) {
            Presence::Denied(reason) => {
                assert!(reason.contains("locked"), "the denial names the path: {reason}");
                assert!(!reason.contains("ENOENT"), "a denial never claims ENOENT: {reason}");
            }
            other => panic!("parent-traversal EACCES must be Denied, got {other:?}"),
        }
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).ok();
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_node_type_is_proven_absence_not_denial() {
        // stat ANSWERED and the type says "regular file": the device is
        // honestly absent (the inode that exists is not the device), and
        // this is not a denial — metadata proved it.
        let dir = scratch("type");
        let f = dir.join("sev-guest");
        fs::write(&f, b"not a device").unwrap();
        match probe_device(&f.to_string_lossy(), is_chardev) {
            Presence::Absent(a) => {
                assert!(a.reason().contains("not the expected device type"), "{}", a.reason());
            }
            other => panic!("a regular file must be Absent (wrong type), got {other:?}"),
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chardev_passes_the_filter_blockdev_does_not() {
        // /dev/null is a chardev on every Linux host: the filter must
        // accept it under is_chardev and reject it under a block-device
        // filter (the type column is real, not always-true).
        assert!(matches!(probe_device("/dev/null", is_chardev), Presence::Present));
        let is_block: fn(u32) -> bool = |m| m & 0o170000 == 0o060000;
        match probe_device("/dev/null", is_block) {
            Presence::Absent(a) => assert!(a.reason().contains("not the expected device type")),
            other => panic!("/dev/null is not a block device, got {other:?}"),
        }
    }

    #[test]
    fn honest_constructor_refuses_non_enoent_errors() {
        // The type-level teeth: Absence::honest is the only public Absent
        // constructor, and it REFUSES every errno class that is not ENOENT.
        let eacces = std::io::Error::from_raw_os_error(13); // EACCES
        assert!(Absence::honest("/dev/tpm0", &eacces).is_none(), "EACCES is never an absence");
        let enotdir = std::io::Error::from_raw_os_error(20);
        assert!(Absence::honest("/dev/tpm0", &enotdir).is_none(), "ENOTDIR is never an absence");
        let enoent = std::io::Error::from_raw_os_error(2);
        assert!(Absence::honest("/dev/tpm0", &enoent).is_some(), "ENOENT is the honest absence");
    }

    struct LawChannel {
        denied: bool,
    }
    impl Channel for LawChannel {
        fn name(&self) -> &'static str {
            "lawtest"
        }
        fn detect(&self) -> Presence {
            if self.denied {
                Presence::Denied("/dev/lawtest: cannot prove absence".into())
            } else {
                Presence::Absent(
                    Absence::honest("/dev/lawtest", &std::io::Error::from_raw_os_error(2))
                        .unwrap(),
                )
            }
        }
        fn collect(&self, _n: &[u8; 64], _o: &[Vec<u8>]) -> Result<Collected, String> {
            Err("collect must not run when detect says absent".into())
        }
    }

    #[test]
    fn denied_detect_renders_failed_row_never_absent_row() {
        // The wire-shape half of the law: Denied -> Failed status (loud);
        // Absent -> Absent status whose reason says ENOENT + the path.
        let denied: Arc<Vec<Box<dyn Channel + Send + Sync>>> =
            Arc::new(vec![Box::new(LawChannel { denied: true })]);
        let (out, status) = collect_all(&denied, &[0u8; 64]);
        assert!(out.is_empty(), "a denied probe never reaches collect");
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].outcome, ChannelOutcome::Failed, "denials are loud");
        assert!(status[0].reason.contains("presence probe denied"), "{}", status[0].reason);

        let absent: Arc<Vec<Box<dyn Channel + Send + Sync>>> =
            Arc::new(vec![Box::new(LawChannel { denied: false })]);
        let (out, status) = collect_all(&absent, &[0u8; 64]);
        assert!(out.is_empty(), "an absent probe never reaches collect");
        assert_eq!(status[0].outcome, ChannelOutcome::Absent);
        assert!(status[0].reason.contains("/dev/lawtest"), "{}", status[0].reason);
        assert!(status[0].reason.contains("ENOENT"), "{}", status[0].reason);
    }
}
