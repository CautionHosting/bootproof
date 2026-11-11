//! The snp verifier: check a SEV-SNP firmware attestation report received
//! over the wire -- all offline, from the Bundle, against the build-pinned
//! AMD KDS roots.
//!
//! Checks (in order; any failure is a NOT PROVEN `memory_encryption` fact
//! with a reason, never a silent drop):
//! 1. `doc` is the full 1184-byte v5 report and decodes to a typed report.
//! 2. `report_data[..32] == nonce` (the 32-byte challenge nonce, echoed in
//!    the front half of the 64-byte report_data): the same nonce the tpm2
//!    quote binds (qualifyingData == nonce) -- one challenge covers both
//!    channels, so a stale or replayed report fails here. The nonce must not
//!    be all-zero (a forgeable binding).
//! 3. The VLEK anchor is present and parses.
//! 4. The firmware report signature (ECDSA P-384 / SHA-384 over the first
//!    672 bytes) verifies against the VLEK.
//! 5. The VLEK chains to the pinned roots: VLEK -> ASVK (SEV-VLEK-Milan)
//!    -> ARK (ARK-Milan), all in-process (sev crypto_nossl).
//! 6. Guest policy meets the memory-encryption baseline: debug disabled
//!    (policy & 0x80000 == 0) and page-swap disabled, i.e. policy == 0x2030000
//!    for a standard CVM.
//! 7. VMPL == 0 (the hypervisor cannot observe or control the guest).

use sev::certs::snp::Certificate;
use sev::firmware::guest::AttestationReport;
use sev::parser::Decoder;
use std::io::Cursor;

use crate::channel::{SnpVerified, Verified, Verifier};
use crate::wire::{Bundle, Evidence, Fact, Status};

/// The full v5 report length the firmware produces.
const REPORT_LEN: usize = 1184;

// The identity-field offsets inside the v5 report. Positive source: the
// AMD SNP ABI table (PUB 40312) as mirrored by sev 8.0.0's own encode/
// decode walk (firmware/guest/types/snp.rs), whose constant CHIP_ID_RANGE
// = 0x1A0..0x1E0 pins the chip_id span; the report's signature field sits
// at 0x2A0 and covers bytes [0, 0x2A0), so EVERY offset below is inside
// the VLEK-signed prefix: once the report signature verifies (the check
// that ran before any of this), these bytes are tamper-evident by
// construction -- an attacker who changes one breaks the signature, which
// fails the channel closed.
const SVN_OFF: usize = 0x04;            // guest_svn, u32 LE
const KEY_INFO_OFF: usize = 0x48;       // key_info, u32 LE (bits 4-5: MASK_CHIPID)
const REPORTED_TCB_OFF: usize = 0x180;  // reported_tcb, 8 raw bytes
const CPUID_OFF: usize = 0x188;         // family, model, stepping (3 x u8)
const CHIP_ID_OFF: usize = 0x1A0;       // chip_id, 64 bytes
const CHIP_ID_LEN: usize = 64;

/// The chip-identity decision rule, shared by facts() and the fixture
/// agreement lane. PROVEN iff the 64-byte CHIP_ID is non-zero.
///
/// The BYTES are always attested (they ride the VLEK signature -- that is
/// never in question). What an all-zero CHIP_ID withholds is the IDENTITY
/// CLAIM: a green row that reads "identity = 0000..." attests nothing
/// about which chip this is -- it is the absence of an identity, not one.
/// Milan-generation firmware is known to emit zeros even with
/// mask_chipid == 0 (witnessed on the captured live report), so this is a
/// live state, not a theoretical one. The all-zero case is the vocabulary
/// the sev crate itself uses (AttestationReportError::MaskedChipId).
pub fn chip_identity_proven(chip_id: &[u8]) -> bool {
    chip_id.iter().any(|b| *b != 0)
}

pub struct SnpVerifier;

impl SnpVerifier {
    /// Decode + verify the snp evidence with the required VMPL. Any failure
    /// returns `Err(reason)` which the caller surfaces as a NOT PROVEN fact.
    pub fn verify_snp_with_vmpl(
        ev: &Evidence,
        nonce: &[u8; 32],
        required_vmpl: u32,
    ) -> Result<SnpVerified, String> {
        let doc = &ev.doc.0;

        // 1. Full v5 report.
        if doc.len() != REPORT_LEN {
            return Err(format!(
                "snp doc is {} bytes, expected the full {REPORT_LEN}-byte v5 report",
                doc.len()
            ));
        }
        let ar = AttestationReport::decode(&mut Cursor::new(doc), ())
            .map_err(|e| format!("snp report decode: {e:?}"))?;
        if ar.version != 5 {
            return Err(format!(
                "snp report version is {}, expected 5",
                ar.version
            ));
        }

        // 2. Nonce binding: report_data must echo the 32-byte challenge
        //    nonce in its front half (the VLEK signature integrity-covers
        //    the full 64 bytes). An all-zero nonce would be forgeable, so
        //    it is rejected too.
        if !crate::snp::nonce_binding_ok(&ar.report_data, nonce) {
            return Err(
                "snp report_data does not echo the challenge nonce (replay or cross-channel \n\
                 binding broken)".into(),
            );
        }

        // 3. VLEK anchor.
        let vlek_der = ev
            .anchors
            .get("vlek")
            .map(|b| b.0.clone())
            .ok_or_else(|| "snp: no VLEK anchor bundled (firmware did not provision one)".to_string())?;
        let vlek = Certificate::from_der(&vlek_der)
            .map_err(|e| format!("snp: VLEK anchor does not parse: {e:?}"))?;

        // 4 + 5. Report signature + chain to the pinned roots.
        let c = crate::snp::check(&ar, &vlek).map_err(|e| format!("snp check: {e}"))?;
        if !c.sig_ok {
            return Err("snp: VLEK did not sign the report (forged or wrong VLEK)".into());
        }
        if !c.chain_ok {
            return Err(format!(
                "snp: VLEK does not chain to the pinned ARK-Milan ({})",
                c.chain_err.as_deref().unwrap_or("unknown")
            ));
        }

        // 6. Guest policy: debug must be disabled, page-swap must be disabled.
        if ar.policy.debug_allowed() {
            return Err(format!(
                "snp: guest policy 0x{:x} allows debug (bit 19 set)",
                ar.policy.0
            ));
        }
        if !ar.policy.page_swap_disabled() {
            return Err(format!(
                "snp: guest policy 0x{:x} does not disable page swap (bit 25 clear)",
                ar.policy.0
            ));
        }

        // 7. VMPL requirement.
        if ar.vmpl != required_vmpl {
            return Err(format!(
                "snp: guest runs at VMPL {}, expected {}",
                ar.vmpl, required_vmpl
            ));
        }

        Ok(SnpVerified {
            report_bytes: doc.to_vec(),
            policy: ar.policy.0,
            vmpl: ar.vmpl,
            report_data: ar.report_data,
            tsme: ar.plat_info.tsme_enabled(),
            version: ar.current.to_string(),
        })
    }

    /// Verify with the required VMPL at VMPL 0 (the memory-encryption
    /// baseline the remote `verify` flow enforces).
    pub fn verify_snp(ev: &Evidence, nonce: &[u8; 32]) -> Result<SnpVerified, String> {
        Self::verify_snp_with_vmpl(ev, nonce, crate::snp::REQUIRED_VMPL)
    }
}

impl Verifier for SnpVerifier {
    fn name(&self) -> &'static str {
        "snp"
    }

    fn verify(
        &self,
        ev: &Evidence,
        nonce: &[u8; 32],
        _bundle: &Bundle,
    ) -> Result<Verified, String> {
        Ok(Verified::Snp(SnpVerifier::verify_snp(ev, nonce)?))
    }

    fn facts(&self, v: &Verified) -> Vec<Fact> {
        let Verified::Snp(v) = v else {
            unreachable!("snp facts called with a non-snp Verified")
        };
        let mut facts = vec![Fact {
            name: "memory_encryption".into(),
            value: format!(
                "SEV-SNP v5 report, debug-disabled policy 0x{:x}, VMPL {}, report_data \
                 echoes the challenge nonce; TSME {}, firmware {}",
                v.policy, v.vmpl, v.tsme, v.version
            ),
            anchors: vec!["snp".into()],
            status: Status::Proven,
        }];

        // The hardware-identity facts (AMI-2). These read the identity
        // fields straight out of the SAME report bytes that just passed
        // every gate in verify_snp_with_vmpl (length, decode, VLEK
        // signature, chain, policy, VMPL): every offset is inside the
        // VLEK-signed prefix, so the bytes are tamper-evident by
        // construction. This is display-of-attested, not a new trust
        // tier: the verification already happened; these rows show WHAT
        // was verified.
        let rb = &v.report_bytes;
        // The verify path guarantees REPORT_LEN bytes (it is the first
        // gate); the defensive zero-status guard below is belt-and-
        // braces for a hand-constructed SnpVerified, never a live path.
        if rb.len() == REPORT_LEN {
            let svn = u32::from_le_bytes([
                rb[SVN_OFF],
                rb[SVN_OFF + 1],
                rb[SVN_OFF + 2],
                rb[SVN_OFF + 3],
            ]);
            let mask_chipid = (u32::from_le_bytes([
                rb[KEY_INFO_OFF],
                rb[KEY_INFO_OFF + 1],
                rb[KEY_INFO_OFF + 2],
                rb[KEY_INFO_OFF + 3],
            ]) >> 4)
                & 3;
            let tcb = &rb[REPORTED_TCB_OFF..REPORTED_TCB_OFF + 8];
            let tcb_hex: String = tcb.iter().map(|b| format!("{b:02x}")).collect();
            let (fam, modl, step) = (rb[CPUID_OFF], rb[CPUID_OFF + 1], rb[CPUID_OFF + 2]);
            let chip = &rb[CHIP_ID_OFF..CHIP_ID_OFF + CHIP_ID_LEN];
            let chip_hex: String = chip.iter().map(|b| format!("{b:02x}")).collect();

            // The CPU identity row: CPUID family.model.stepping + the
            // guest SVN + the reported TCB the VCEK/VLEK was derived at.
            // These survive the Milan chip_id-zero problem: the model
            // number is real even when the chip serial is blanked.
            facts.push(Fact {
                name: "snp_cpu_identity".into(),
                value: format!(
                    "CPUID family {fam} model {modl} stepping {step}; guest_svn {svn}; \
                     reported_tcb {tcb_hex} (bytes @0x180)",
                ),
                anchors: vec!["snp".into()],
                status: Status::Proven,
            });

            // The chip identity row: PROVEN iff non-zero (the zero-rule:
            // see chip_identity_proven). The bytes are always quoted --
            // attested either way; the status tracks whether they name a
            // chip at all.
            let proven = chip_identity_proven(chip);
            facts.push(Fact {
                name: "snp_chip_identity".into(),
                value: if proven {
                    format!("CHIP_ID {chip_hex} (64 bytes @0x1A0, VLEK-signed)")
                } else {
                    format!(
                        "firmware reports CHIP_ID as zero (mask_chipid={mask_chipid}): \
                         chip identity not reportable on this firmware generation"
                    )
                },
                anchors: vec!["snp".into()],
                status: if proven { Status::Proven } else { Status::NotProven },
            });
        }

        // THE IDENTITY-TAIL ROW (bake-11 #2, the SPKI tail fold). The tail is
        // `report_data[32..64]`, INSIDE the VLEK-signed prefix every gate in
        // `verify_snp` just cleared, so these 32 bytes are tamper-evident by
        // construction: a transport that flips the tail breaks the report
        // signature and the channel dies BEFORE this fact is ever built. This
        // is display-of-attested, not a new trust tier.
        //
        // CLASSIFY LAW (the fold adjudication): tail content NEVER fails.
        // FAILED belongs to the signature, not the content. The three states:
        // all-zero => NotEnabled (honest pre-fold); non-zero + named candidate
        // match => Matched; non-zero + no match => Unattributed (honest, never
        // a lie). At CORE SCOPE the candidate set is EMPTY BY LAW: the signer
        // key (`keys.sign.pub_`) is a platform-scoped encoding (TPMT_PUBLIC)
        // that the core must not parse, and the SPKI pin belongs to the TLS
        // leaf, which is not in the Bundle. So the core can only ever emit
        // NotEnabled or Unattributed — it can report the fold STATE but never
        // attribute the tail to a named key. The Matched arm is reached only
        // where a platform/envelope supplies a candidate (wardend parses its
        // own signer pin, the browser mirrors) and, until #19 lands the
        // out-of-band expected pin, even a Matched row is tier-labeled
        // "same-attacker", never a browser-trusted identity. The Matched arm
        // below is therefore unreachable at core scope (empty candidates); it
        // is kept exhaustive so the verbatim label is defined in one place.
        let mut tail = [0u8; 32];
        tail.copy_from_slice(&v.report_data[32..64]);
        let cands: [(&'static str, [u8; 32]); 0] = [];
        let (value, status) = match crate::snp::classify_identity_tail(&tail, &cands) {
            crate::snp::IdentityTail::NotEnabled => (
                "identity fold not enabled (report_data[32..64] all zero): this bundle \
                 predates the SPKI tail fold, tier-1 key binding absent"
                    .to_string(),
                Status::NotProven,
            ),
            crate::snp::IdentityTail::Unattributed => (
                crate::snp::identity_tail_reason(&tail, &cands),
                Status::NotProven,
            ),
            crate::snp::IdentityTail::Matched(name) => (
                format!("identity tail matches {name}: attested identity, same-attacker bound until #19"),
                Status::Proven,
            ),
        };
        facts.push(Fact {
            name: "snp_identity_tail".into(),
            value,
            anchors: vec!["snp".into()],
            status,
        });
        facts
    }

    // memory_encryption is the fact this channel owns: when the report is
    // present but fails any check, it is NOT PROVEN with the reason, never
    // silently dropped.
    fn failed_fact(&self, _ev: &Evidence, reason: &str) -> Option<Fact> {
        Some(Fact {
            name: "memory_encryption".into(),
            value: format!("SEV-SNP report present but NOT verified: {reason}"),
            anchors: vec!["snp".into()],
            status: Status::NotProven,
        })
    }

    // AMI-2: the snp channel owns FOUR facts (memory_encryption + the three
    // identity rows: cpu, chip, tail), so a failed report must NOT PROVEN all
    // four -- a tampered report's identity bytes are untrustworthy exactly as
    // the memory-encryption claim is. This is load-bearing for the
    // identity-tail row specifically: an all-zero or attacker-shaped tail on
    // a report that FAILED the signature must read NOT PROVEN, never a
    // NotEnabled/Unattributed that would imply the bytes were attested. The
    // JS verifier reaches the same verdict through its own path (the identity
    // subs are gated on the report signature); this is the two-verifiers-one-
    // verdict parity on the tamper path. The required-absent case is NOT
    // overridden: an absent report has no bytes, so the identity rows are
    // absent (not NOT PROVEN) in both verifiers -- honest silence, distinct
    // from a tampered report's present-row-says-NOT-PROVEN.
    fn failed_facts(&self, ev: &Evidence, reason: &str) -> Vec<Fact> {
        let mut facts = Vec::with_capacity(4);
        if let Some(f) = self.failed_fact(ev, reason) {
            facts.push(f);
        }
        let why = format!("snp report NOT verified ({reason}): identity bytes unattested");
        for name in ["snp_cpu_identity", "snp_chip_identity", "snp_identity_tail"] {
            facts.push(Fact {
                name: name.into(),
                value: why.clone(),
                anchors: vec!["snp".into()],
                status: Status::NotProven,
            });
        }
        facts
    }

    // memory_encryption is also the fact this channel owns when it is
    // REQUIRED but ABSENT from the bundle: NOT PROVEN "absent", never
    // silently dropped (a node that does not serve the snp channel at all).
    fn required_absent_fact(&self) -> Option<Fact> {
        Some(Fact {
            name: "memory_encryption".into(),
            value: "not proven: the node does not serve a SEV-SNP channel \
                     (no /dev/sev-guest at the node)"
                .into(),
            anchors: vec!["snp".into()],
            status: Status::NotProven,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::B64;
    use std::collections::BTreeMap;

    const REPORT: &[u8] = include_bytes!("../trust/data/snp-report-fixture.bin");
    const REQUEST: &[u8] = include_bytes!("../trust/data/snp-request-fixture.bin");
    const VLEK: &[u8] = include_bytes!("../trust/data/snp-vlek-fixture.pem");

    /// The challenge nonce that produced the fixture: the 32-byte client
    /// challenge echoed in the front half of the 64-byte report_data (the
    /// back 32 bytes were firmware-chosen at capture time).
    fn fixture_nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        n.copy_from_slice(&REQUEST[..32]);
        n
    }

    fn vlek_der() -> Vec<u8> {
        let c = Certificate::from_pem(VLEK).unwrap();
        c.to_der().unwrap()
    }

    fn evidence(doc: &[u8], vlek: Option<Vec<u8>>) -> Evidence {
        let mut anchors = BTreeMap::new();
        if let Some(v) = vlek {
            anchors.insert("vlek".into(), B64::new(v));
        }
        Evidence {
            channel: "snp".into(),
            doc: B64::new(doc.to_vec()),
            anchors,
        }
    }

    #[test]
    fn verifier_proves_fixture_report() {
        let ev = evidence(REPORT, Some(vlek_der()));
        // The fixture was captured at VMPL 1 (the pre-channel trust path
        // requested VMPL 1); a verifier for that node accepts it.
        let v =
            SnpVerifier::verify_snp_with_vmpl(&ev, &fixture_nonce(), 1).expect("fixture must verify");
        assert_eq!(v.policy, 0x2030000);
        assert_eq!(v.vmpl, 1, "fixture report was captured at VMPL 1");
        assert!(v.tsme, "TSME (total memory encryption) is on the fixture platform");
        assert!(v.version.contains("1.58"), "firmware version: {}", v.version);
        // facts() must report memory_encryption as PROVEN.
        let facts = SnpVerifier.facts(&Verified::Snp(v));
        let me = facts.iter().find(|f| f.name == "memory_encryption").unwrap();
        assert_eq!(me.status, Status::Proven);
        assert!(me.anchors.iter().any(|a| a == "snp"));
    }

    #[test]
    fn verifier_rejects_wrong_vmpl() {
        // The fixture runs at VMPL 1; a strict VMPL-0 verifier (the
        // memory-encryption baseline) must reject it with a reason.
        let ev = evidence(REPORT, Some(vlek_der()));
        let err = SnpVerifier::verify_snp_with_vmpl(&ev, &fixture_nonce(), 0).unwrap_err();
        assert!(err.contains("VMPL"), "got: {err}");
    }

    #[test]
    fn verifier_rejects_wrong_nonce() {
        let mut nonce = fixture_nonce();
        nonce[0] ^= 0x01;
        let ev = evidence(REPORT, Some(vlek_der()));
        let err = SnpVerifier::verify_snp(&ev, &nonce).unwrap_err();
        assert!(
            err.contains("report_data") && err.contains("nonce"),
            "got: {err}"
        );
    }

    #[test]
    fn verifier_rejects_truncated_report() {
        let mut doc = REPORT.to_vec();
        doc.truncate(REPORT_LEN - 1);
        let ev = evidence(&doc, Some(vlek_der()));
        let err = SnpVerifier::verify_snp(&ev, &fixture_nonce()).unwrap_err();
        assert!(err.contains("bytes"), "got: {err}");
    }

    #[test]
    fn verifier_rejects_missing_vlek() {
        let ev = evidence(REPORT, None);
        let err = SnpVerifier::verify_snp(&ev, &fixture_nonce()).unwrap_err();
        assert!(err.contains("VLEK"), "got: {err}");
    }

    #[test]
    fn verifier_rejects_wrong_vlek_signature() {
        // A valid P-384 cert that did NOT sign the report (the pinned ARK):
        // the report signature check must fail.
        let wrong = Certificate::from_pem(crate::snp::AMD_ARK_MILAN_PEM).unwrap();
        let ev = evidence(REPORT, Some(wrong.to_der().unwrap()));
        let err = SnpVerifier::verify_snp(&ev, &fixture_nonce()).unwrap_err();
        assert!(err.contains("did not sign"), "got: {err}");
    }

    #[test]
    fn verifier_rejects_tampered_report_bytes() {
        // Flip the policy ABI-minor byte (offset 0x09, inside the signed
        // prefix) so the decoded report differs from what the VLEK signed:
        // the signature check must fail.
        let mut doc = REPORT.to_vec();
        doc[0x09] ^= 0x01;
        let ev = evidence(&doc, Some(vlek_der()));
        let err = SnpVerifier::verify_snp(&ev, &fixture_nonce()).unwrap_err();
        assert!(
            err.contains("did not sign") || err.contains("report"),
            "got: {err}"
        );
    }

    #[test]
    fn verifier_rejects_replayed_zero_nonce_report() {
        // An all-zero challenge nonce: the binding is forgeable, so the
        // verifier must reject it even when the report's report_data
        // happens to echo it in the front half.
        let nonce = [0u8; 32];
        let mut doc = REPORT.to_vec();
        // report_data is at offset 0x50 (80); zero the front half to match
        // the all-zero nonce (the signature then also fails, which is fine:
        // we only need a clean rejection, not a panic).
        for i in 0x50..0x50 + 32 {
            doc[i] = 0;
        }
        let ev = evidence(&doc, Some(vlek_der()));
        let err = SnpVerifier::verify_snp(&ev, &nonce).unwrap_err();
        assert!(
            err.contains("nonce") || err.contains("did not sign"),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // AMI-2: the hardware-identity facts (chip_id zero-rule, CPU model,
    // the tamper parity, and the trait-default wrapper).
    // -----------------------------------------------------------------------

    /// POSITIVE-FIRST + golden vectors: the fixture report passes every
    /// gate, so facts() must carry all four facts with the pinned
    /// Milan-generation values: CPU identity PROVEN (the model number is
    /// real even when the serial is blanked -- the operator's ask), chip
    /// identity NOT PROVEN with the zero-rule reason (the firmware emits
    /// zeros; a green row naming 64 zero bytes would attest nothing), and
    /// the identity-tail row NOT PROVEN as UNATTRIBUTED (the fixture tail is
    /// non-zero -- a pre-fold host folded a 32-byte value -- and the core
    /// carries no signer-key candidate, so it reports the fold state without
    /// attributing it; never FAILED). The memory_encryption fact riding
    /// PROVEN in the same call is the witness that the identity NOT PROVENs
    /// are the zero-rule + unattributed-fold, not a broken channel.
    #[test]
    fn identity_facts_pin_the_milan_fixture() {
        let ev = evidence(REPORT, Some(vlek_der()));
        let v = SnpVerifier::verify_snp_with_vmpl(&ev, &fixture_nonce(), 1).expect("verifies");
        let facts = SnpVerifier.facts(&Verified::Snp(v));
        assert_eq!(facts.len(), 4, "four facts: {facts:?}");
        let mem = facts.iter().find(|f| f.name == "memory_encryption").unwrap();
        assert_eq!(mem.status, Status::Proven);
        let cpu = facts.iter().find(|f| f.name == "snp_cpu_identity").unwrap();
        assert_eq!(cpu.status, Status::Proven);
        assert_eq!(
            cpu.value,
            "CPUID family 25 model 1 stepping 1; guest_svn 0; reported_tcb \
             0400000000001dde (bytes @0x180)",
            "the CPU identity golden vector drifted"
        );
        let chip = facts.iter().find(|f| f.name == "snp_chip_identity").unwrap();
        assert_eq!(chip.status, Status::NotProven, "Milan fixture: chip_id is zeros");
        assert!(
            chip.value.contains("firmware reports CHIP_ID as zero")
                && chip.value.contains("chip identity not reportable"),
            "the zero-rule reason verbatim: {}",
            chip.value
        );
        // The mask_chipid decode rides the reason (0 here: the zeros are
        // a firmware-generation behavior, NOT a mask setting -- the exact
        // surprise this fact exists to surface honestly).
        assert!(chip.value.contains("mask_chipid=0"), "got: {}", chip.value);
        // The identity-tail row: the fixture tail is non-zero and the core
        // has no signer-key candidate, so it is UNATTRIBUTED (never FAILED),
        // and the reason NAMES the measured tail hex (the auditor law).
        let tail = facts.iter().find(|f| f.name == "snp_identity_tail").unwrap();
        assert_eq!(tail.status, Status::NotProven, "core scope: never attributes");
        assert!(
            tail.value.contains("unattributed")
                && tail.value.contains("744938841637f5f20d64e252545d333a201aa88a3210e1100bf04d6adab8f106"),
            "the tail reason must name the measured hex: {}",
            tail.value
        );
    }

    /// The zero-rule decision fn, pinned at unit level: all-zero is not
    /// an identity; a single byte anywhere makes it one. The non-zero
    /// PROVEN path cannot be end-to-end fixtured with the pinned Milan
    /// roots (only AMD's Milan KDS signs reports those verifiers accept;
    /// wardend's prod is the same zero-emitting generation), so the fn +
    /// these vectors are the pin until first Genoa/Turin hardware lives
    /// the PROVEN path.
    #[test]
    fn chip_identity_proven_zero_rule() {
        assert!(!chip_identity_proven(&[0u8; 64]), "all-zero is not an identity");
        let mut one = [0u8; 64];
        one[63] = 1;
        assert!(chip_identity_proven(&one), "one byte anywhere is an identity");
        let mut first = [0u8; 64];
        first[0] = 0xab;
        assert!(chip_identity_proven(&first));
        let real = [0xd1u8; 64];
        assert!(chip_identity_proven(&real));
    }

    /// The non-zero PROVEN fact text, pinned at unit level on a
    /// hand-constructed SnpVerified (facts() does no verification -- the
    /// gates above it do; this isolates the fact rendering): the hex of
    /// the bytes + the offset provenance, PROVEN.
    #[test]
    fn nonzero_chip_id_fact_reads_proven_with_hex() {
        let mut rb = REPORT.to_vec();
        // Write an identity into the chip_id span (the sig is now stale,
        // but facts() never checks it -- verify() did, on real bytes).
        for (i, b) in rb[CHIP_ID_OFF..CHIP_ID_OFF + CHIP_ID_LEN].iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        let v = SnpVerified {
            report_bytes: rb,
            policy: 0x2030000,
            vmpl: 0,
            report_data: [0u8; 64],
            tsme: true,
            version: "1.58.1".into(),
        };
        let facts = SnpVerifier.facts(&Verified::Snp(v));
        let chip = facts.iter().find(|f| f.name == "snp_chip_identity").unwrap();
        assert_eq!(chip.status, Status::Proven);
        assert!(
            chip.value.starts_with("CHIP_ID 01020304") && chip.value.contains("@0x1A0"),
            "got: {}",
            chip.value
        );
    }

    /// NEGATIVE TWIN (the chip_id offset sits under the signature): flip
    /// ONE byte at 0x1A0 -- inside the signed prefix, outside every other
    /// check's field -- and the VLEK signature must reject the report.
    /// The identity claim cannot be tampered without breaking the chain
    /// of trust that makes it attested.
    #[test]
    fn a_flipped_chip_id_byte_breaks_the_report_signature() {
        let mut doc = REPORT.to_vec();
        doc[CHIP_ID_OFF] ^= 0x01;
        let ev = evidence(&doc, Some(vlek_der()));
        let err = SnpVerifier::verify_snp(&ev, &fixture_nonce()).unwrap_err();
        assert!(err.contains("did not sign"), "got: {err}");
    }

    /// TAMPER PARITY (Option A, both sides): a failed report must NOT
    /// PROVEN ALL FOUR owned facts, matching the JS verifier's behavior on
    /// the same bundle (its identity subs are gated on the report
    /// signature). Before the plural override, the identity facts were
    /// ABSENT on the Rust side while JS rendered them NOT PROVEN -- the
    /// exact asymmetry the agreement gate kills. The identity-tail row is
    /// the fourth: on a tampered report its bytes are unattested, so it must
    /// read NOT PROVEN, never the NotEnabled/Unattributed it would emit on
    /// the SUCCESS path (which would imply the tampered bytes were attested).
    #[test]
    fn a_failed_report_not_provens_all_four_facts() {
        let mut doc = REPORT.to_vec();
        doc[CHIP_ID_OFF] ^= 0x01;
        let ev = evidence(&doc, Some(vlek_der()));
        let reason = SnpVerifier::verify_snp(&ev, &fixture_nonce()).unwrap_err();
        let facts = SnpVerifier.failed_facts(&ev, &reason);
        let names: Vec<&str> = facts.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "memory_encryption",
                "snp_cpu_identity",
                "snp_chip_identity",
                "snp_identity_tail"
            ],
            "one failure, four honest facts"
        );
        assert!(facts.iter().all(|f| f.status == Status::NotProven));
        assert!(facts[1].value.contains("identity bytes unattested"));
    }

    /// CONDITION (a): the trait DEFAULT is byte-identical for a
    /// non-overriding verifier. A minimal channel that implements only
    /// the singular failed_fact must get exactly that one fact through
    /// failed_facts (and one through required_absent_facts) -- tpm2,
    /// wardend, and the engine test mocks never touched the plural and
    /// behave as before.
    #[test]
    fn the_plural_default_wraps_the_singular_exactly() {
        struct SingularOnly;
        impl Verifier for SingularOnly {
            fn name(&self) -> &'static str {
                "singular-only"
            }
            fn verify(&self, _ev: &Evidence, _n: &[u8; 32], _b: &Bundle) -> Result<Verified, String> {
                Err("never verifies".into())
            }
            fn facts(&self, _v: &Verified) -> Vec<Fact> {
                vec![]
            }
            fn failed_fact(&self, _ev: &Evidence, reason: &str) -> Option<Fact> {
                Some(Fact {
                    name: "sole_fact".into(),
                    value: reason.to_string(),
                    anchors: vec![],
                    status: Status::NotProven,
                })
            }
            // NO plural overrides: the defaults must do the work.
        }
        let ev = Evidence {
            channel: "singular-only".into(),
            doc: crate::wire::B64::new(vec![]),
            anchors: BTreeMap::new(),
        };
        let failed = SingularOnly.failed_facts(&ev, "because");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].name, "sole_fact");
        assert_eq!(failed[0].value, "because");
        // The absent default wraps None exactly (tpm2-style: owns no
        // required-absent fact -> zero facts, not a fabricated one).
        assert!(SingularOnly.required_absent_facts().is_empty());
    }

}
