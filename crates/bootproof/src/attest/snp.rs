//! The `snp` channel: a fresh, nonce-bound SEV-SNP firmware attestation
//! report, issued in-process against the configured SNP guest device
//! (default `/dev/sev-guest`).
//!
//! Per-request flow (stateless, no hardware state, no `Command::new`):
//! 1. Presence is a METADATA probe of the CONFIGURED device (THE PRESENCE
//!    LAW + THE ABSENCE LAW — see `channel::probe_device`): ENOENT-class
//!    absence degrades the Bundle to tpm2-only (honest, with the probed
//!    path named on the wire); any other stat errno is a LOUD Failed row,
//!    never an absence.
//! 2. Otherwise issue `SNP_GET_EXT_REPORT` with the FULL 64-byte challenge
//!    nonce in `report_data` (its front 32 bytes are the client's 32-byte
//!    challenge — what `verify/snp.rs` checks; the back 32 are bound by the
//!    VLEK signature) and request `VMPL 0` (the report echoes the VMPL the
//!    guest runs at).
//! 3. Publish the full 1184-byte v5 report as the `doc`, and the
//!    platform-provisioned VLEK certificate (DER) as the `vlek` anchor so
//!    the verifier can check the report signature and chain it to AMD's
//!    pinned roots.
//!
//! The snp `doc` is the raw firmware report, verbatim (what the firmware
//! signed). The verifier decodes it, checks the VLEK signature, the
//! VLEK -> ASVK -> ARK chain, the debug-disabled policy, the VMPL, and the
//! `report_data == challenge nonce` binding.
//!
//! The path seam (gate unification (2)): the vendored `sev` crate's
//! `Firmware::open()` hardcodes `/dev/sev-guest` and exposes no
//! From<File>/injection seam, so the CONFIGURED path can honestly drive
//! PRESENCE but cannot drive the ioctl. A configured path that differs
//! from the ioctl's hardcoded device is a config-divergence the channel
//! refuses LOUD at collect (the BUG-12 lineage: a sensor that probes one
//! device while the serve path opens another is not reporting the
//! configured device). Zero-arg construction keeps the default and is
//! byte-identical to the pre-seam behavior.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::channel::{probe_device, is_chardev, Channel, Collected, Presence};
use crate::snp;
use crate::wire::{B64, Evidence};

/// The snp channel. Holds only the configured device path; detection is
/// per-request (the device may appear/disappear under the process, e.g. a
/// live-migrated guest).
pub struct Snp {
    device: PathBuf,
}

impl Default for Snp {
    fn default() -> Self {
        Self::new()
    }
}

impl Snp {
    /// The default device (`/dev/sev-guest`).
    pub fn new() -> Self {
        Self {
            device: PathBuf::from(snp::DEV_SEV_GUEST),
        }
    }

    /// The channel against a CONFIGURED device path (the wardend `sev_path`
    /// seam). The presence probe honors this path; the collect path fails
    /// LOUD when the configured path diverges from the device the vendor
    /// firmware library can actually open (see the module docs).
    pub fn at(device: impl Into<PathBuf>) -> Self {
        Self { device: device.into() }
    }

    /// The configured device path (audit + tests).
    pub fn device(&self) -> &std::path::Path {
        &self.device
    }
}

impl Channel for Snp {
    fn name(&self) -> &'static str {
        "snp"
    }

    fn detect(&self) -> Presence {
        // THE PRESENCE LAW: metadata probe, never an open. The probed path
        // is the CONFIGURED one, so the Absent reason on the wire names it
        // (a config divergence is auditable from the page).
        probe_device(&self.device.to_string_lossy(), is_chardev)
    }

    fn collect(&self, nonce: &[u8; 64], _other_docs: &[Vec<u8>]) -> Result<Collected, String> {
        // Re-probe (the device may have vanished mid-flight). Absence here
        // is a Failed row with the honest reason, never a half report.
        match self.detect() {
            Presence::Present => {}
            Presence::Absent(a) => return Err(format!("snp: {}", a.reason())),
            Presence::Denied(reason) => return Err(format!("snp: {reason}")),
        }
        // The divergence gate (see the module docs): the vendored ioctl
        // speaks ONLY the default device. Attesting through the default
        // while the config names another path would report a DIFFERENT
        // device than the configuration promises — refuse LOUD.
        if self.device != std::path::Path::new(snp::DEV_SEV_GUEST) {
            return Err(format!(
                "snp: configured device {} diverges from the device the firmware \
                 library opens ({}) — refusing to attest a device other than \
                 configured (wire the vendored ioctl to the configured path)",
                self.device.display(),
                snp::DEV_SEV_GUEST
            ));
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

    #[test]
    fn configured_path_is_visible_and_defaulted() {
        // Zero-arg construction keeps the default path byte-for-byte.
        assert_eq!(Snp::new().device(), std::path::Path::new("/dev/sev-guest"));
        assert_eq!(Snp::at("/dev/sev-guest-custom").device().to_str().unwrap(), "/dev/sev-guest-custom");
    }

    #[test]
    fn divergence_between_configured_path_and_ioctl_fails_loud() {
        // The (2) seam: a configured device the vendored ioctl cannot speak
        // must FAIL LOUD at collect, never silently attest the default
        // device (the BUG-12 lineage: the sensor and the serve path must
        // name the SAME device). On a real SNP host this proves the gate
        // fires BEFORE the ioctl; off-host the presence probe fires first,
        // so the gate text is asserted where the probe is satisfied.
        let nonce = [7u8; 64];
        let c = Snp::at("/nonexistent/sev-guest");
        let e = c.collect(&nonce, &[]).unwrap_err();
        // Off-host both gates read honestly: the ENOENT absence names the
        // CONFIGURED path (never the hardcoded default).
        assert!(e.contains("/nonexistent/sev-guest"), "reason must name the configured path: {e}");
        assert!(e.contains("ENOENT") || e.contains("diverges"), "honest reason: {e}");
    }
}
