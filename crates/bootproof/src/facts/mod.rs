//! System-fact collectors: local, self-reported facts about the node (CPU,
//! OS, kernel, disks, TPM vendor, SEV-SNP presence).
//!
//! These ride alongside the cryptographically-verified attestation as
//! supporting context. The signed COSE document + PCR state remains the
//! authoritative, verifiable evidence; the facts are what the node reports
//! about its own hardware/software, which a verifier can cross-check
//! against the PCR evidence (e.g. the kernel-config PCR).

use serde::Serialize;

/// A TPM's identifying properties (from `TPM2_GetCapability` / `get_property`).
#[derive(Debug, Clone, Serialize)]
pub struct TpmFacts {
    /// TPM vendor string (the 4-char manufacturer, ASCII).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// TPM firmware version 1 (`TPM_PT_FIRMWARE_VERSION_1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<u32>,
}

/// SEV-SNP attestation device presence.
#[derive(Debug, Clone, Serialize)]
pub struct SnpFacts {
    /// Whether `/dev/sev-guest` is present on the platform.
    pub present: bool,
}

/// Collected local system facts.
#[derive(Debug, Clone, Serialize)]
pub struct Facts {
    /// CPU model name (from `/proc/cpuinfo` "model name").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    /// Number of logical CPUs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<u32>,
    /// OS pretty name (from `/etc/os-release` PRETTY_NAME).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Kernel release string (from `/proc/sys/kernel/osrelease`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// Block-device / volume layout (lsblk summary lines).
    #[serde(default)]
    pub disks: Vec<String>,
    /// TPM identifying properties (if a TPM was available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm: Option<TpmFacts>,
    /// SEV-SNP device presence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snp: Option<SnpFacts>,
}

impl Facts {
    /// Collect CPU, OS, kernel, disk, and SEV-SNP facts from local files.
    /// `tpm` (if provided) is used for the TPM vendor/firmware facts and
    /// must already be started.
    pub fn collect(tpm: Option<&mut bootproof_tpm::Tpm>) -> Self {
        Self {
            cpu_model: cpu_model(),
            cpu_count: cpu_count(),
            os: os_pretty_name(),
            kernel: kernel_release(),
            disks: disk_summary(),
            tpm: tpm.map(tpm_facts),
            snp: Some(snp_facts()),
        }
    }
}

/// The "model name" line of /proc/cpuinfo.
fn cpu_model() -> Option<String> {
    let s = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("model name") {
            let v = v.split(':').nth(1)?.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Count the "processor" entries in /proc/cpuinfo.
fn cpu_count() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let n = s
        .lines()
        .filter(|l| l.trim_start().starts_with("processor") && l.contains(':'))
        .count();
    if n > 0 {
        Some(n as u32)
    } else {
        None
    }
}

/// OS name from /etc/os-release: prefer PRETTY_NAME, then NAME, then ID.
/// (StageX ships NAME/ID but no PRETTY_NAME.)
fn os_pretty_name() -> Option<String> {
    let s = std::fs::read_to_string("/etc/os-release").ok()?;
    for key in ["PRETTY_NAME=", "NAME=", "ID="] {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix(key) {
                let v = v
                    .trim()
                    .trim_matches('"')
                    .trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .trim()
                    .to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Kernel release from /proc/sys/kernel/osrelease.
fn kernel_release() -> Option<String> {
    let s = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let v = s.trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Block-device / volume layout. Prefers `lsblk`; falls back to
/// /proc/partitions if lsblk is unavailable or fails.
fn disk_summary() -> Vec<String> {
    if let Ok(out) = std::process::Command::new("lsblk")
        .args(["-bno", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"])
        .output()
    {
        if out.status.success() {
            let lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .skip(1)
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            if !lines.is_empty() {
                return lines;
            }
        }
    }
    match std::fs::read_to_string("/proc/partitions") {
        Ok(s) => s.lines().skip(2).map(str::to_string).collect(),
        Err(_) => Vec::new(),
    }
}

/// TPM vendor + firmware version via get_property.
/// `TPM_PT_MANUFACTURER` = 0x0105, `TPM_PT_FIRMWARE_VERSION_1` = 0x010B.
fn tpm_facts(tpm: &mut bootproof_tpm::Tpm) -> TpmFacts {
    let vendor = tpm
        .get_property(0x0000_0105)
        .ok()
        .map(|v| {
            v.to_be_bytes()
                .iter()
                .map(|x| if x.is_ascii_alphanumeric() { *x as char } else { '.' })
                .collect()
        });
    let firmware_version = tpm.get_property(0x0000_010B).ok();
    TpmFacts {
        vendor,
        firmware_version,
    }
}

/// SEV-SNP device presence.
fn snp_facts() -> SnpFacts {
    SnpFacts {
        present: std::path::Path::new("/dev/sev-guest").exists(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_sane_shape() {
        // On a Linux test host this should at least find a kernel release.
        let f = Facts::collect(None);
        assert!(f.kernel.is_some() || f.os.is_some());
    }

    #[test]
    fn cpu_model_parses_fixture() {
        // Synthetic /proc/cpuinfo-style parse check via the strip logic.
        let line = "model name\t\t: AMD EPYC 7K83 64-Core Processor";
        let v = line
            .strip_prefix("model name")
            .and_then(|v| v.split(':').nth(1))
            .map(str::trim)
            .unwrap();
        assert!(v.starts_with("AMD EPYC"));
    }
}
