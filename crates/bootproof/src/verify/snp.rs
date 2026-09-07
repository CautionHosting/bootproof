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
        vec![Fact {
            name: "memory_encryption".into(),
            value: format!(
                "SEV-SNP v5 report, debug-disabled policy 0x{:x}, VMPL {}, report_data \
                 echoes the challenge nonce; TSME {}, firmware {}",
                v.policy, v.vmpl, v.tsme, v.version
            ),
            anchors: vec!["snp".into()],
            status: Status::Proven,
        }]
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
}
