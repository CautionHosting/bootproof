//! The `snp` channel: a fresh, nonce-bound SEV-SNP firmware attestation
//! report, issued in-process against `/dev/sev-guest`.
//!
//! Per-request flow (stateless, no hardware state, no `Command::new`):
//! 1. If `/dev/sev-guest` is absent (QEMU dev / non-SNP host) the channel
//!    reports itself unavailable and the Bundle is tpm2-only: graceful
//!    degradation, never a request failure.
//! 2. Otherwise issue `SNP_GET_EXT_REPORT` with the FULL 64-byte challenge
//!    nonce in `report_data` (its front 32 bytes are the client's 32-byte
//!    challenge — what `verify/snp.rs` checks; the back 32 are bound by the
//!    VLEK signature) and request `VMPL 0` (the report echoes the VMPL the
//!    guest runs at).
//! 3. Publish the full 1184-byte v5 report as the `doc`, and the full
//!    endorsement chain as anchors: the platform-provisioned VLEK cert
//!    (DER) plus the build-time-baked AMD KDS roots (`asvk`, `ark`). The
//!    bundle verifies with NOTHING external: the verifier checks the
//!    report signature, chains the VLEK, and pins the bundled roots
//!    against its own baked copy.
//!
//! The snp `doc` is the raw firmware report, verbatim (what the firmware
//! signed). The verifier decodes it, checks the VLEK signature, the
//! VLEK -> ASVK -> ARK chain, the debug-disabled policy, the VMPL, and the
//! `report_data == challenge nonce` binding.

use std::collections::BTreeMap;

use crate::channel::{Channel, Collected};
use crate::snp;
use crate::wire::{B64, Evidence};

/// The snp channel. Holds no state; detection is per-request (the device may
/// appear/disappear under the process, e.g. a live-migrated guest).
pub struct Snp;

impl Default for Snp {
    fn default() -> Self {
        Self
    }
}

impl Snp {
    pub fn new() -> Self {
        Self
    }
}

impl Channel for Snp {
    fn name(&self) -> &'static str {
        "snp"
    }

    fn detect(&self) -> bool {
        snp::device_present()
    }

    fn collect(&self, nonce: &[u8; 64], _other_docs: &[Vec<u8>]) -> Result<Collected, String> {
        // Graceful degradation: no device -> the channel is simply not part
        // of the Bundle. The caller (attest::attestation) skips channels that
        // are not detected, so on a non-SNP host this path is never reached;
        // but if it is (device vanished mid-flight), fail cleanly rather than
        // produce a half report.
        if !snp::device_present() {
            return Err("snp: /dev/sev-guest not present".to_string());
        }

        // The FULL 64-byte challenge is echoed into report_data verbatim
        // (front 32 == the client's 32-byte nonce, which verify/snp.rs
        // checks; the back 32 are integrity-covered by the VLEK signature).
        let ext = snp::issue_report(*nonce, snp::REQUIRED_VMPL)?;

        let mut anchors = BTreeMap::new();
        if let Some(vlek) = &ext.vlek {
            let der = vlek
                .to_der()
                .map_err(|e| format!("encode VLEK DER: {e}"))?;
            anchors.insert("vlek".into(), B64::new(der));
        }

        // Bundle-carried full-chain (the self-containment goal): ship the
        // vendor-published endorsement roots (ASVK + ARK) alongside the
        // VLEK so the bundle verifies with NOTHING external. These are the
        // build-time-baked AMD KDS roots (identical to what the offline
        // verifier chains against); publishing them is byte-stable because
        // the bundle carries the PEM-body DER via the same canonical walk
        // (`pem_body_der`) the browser pin-checks and the drift-killer test
        // pins, so the served bytes hash under the SAME SPKI pin every
        // verifier expects. A swapped root fails closed at every verifier
        // (Rust: verify/snp.rs pin gate; JS: snp.asvk_pin / snp.ark_pin) --
        // bundling a root does NOT weaken the chain, it only removes the
        // external-fetch dependency.
        if let Some(asvk) = snp::pem_body_der(snp::AMD_ASVK_MILAN_PEM) {
            anchors.insert("asvk".into(), B64::new(asvk));
        }
        if let Some(ark) = snp::pem_body_der(snp::AMD_ARK_MILAN_PEM) {
            anchors.insert("ark".into(), B64::new(ark));
        }

        let evidence = Evidence {
            channel: "snp".into(),
            doc: B64::new(ext.report_bytes),
            anchors,
        };
        Ok(Collected {
            evidence,
            keys: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_maps_to_left_padded_report_data() {
        let nonce: [u8; 32] = [0x42u8; 32];
        let rd = snp::report_data_for_nonce(&nonce);
        assert_eq!(&rd[..32], &nonce[..]);
        assert_eq!(&rd[32..], &[0u8; 32]);
    }

    #[test]
    fn nonce_mapping_is_injective() {
        // Distinct nonces -> distinct report_data.
        let a = snp::report_data_for_nonce(&[1u8; 32]);
        let b = snp::report_data_for_nonce(&[2u8; 32]);
        assert_ne!(a, b);
        // The verifier's nonce-binding check depends on the channel's
        // mapping: report_data's front half must echo the nonce (and the
        // nonce must be non-zero).
        let n: [u8; 32] = [0x7eu8; 32];
        let rd = snp::report_data_for_nonce(&n);
        assert!(snp::nonce_binding_ok(&rd, &n));
    }

    #[test]
    fn channel_name_is_snp() {
        let c = Snp::new();
        assert_eq!(c.name(), "snp");
    }
}
