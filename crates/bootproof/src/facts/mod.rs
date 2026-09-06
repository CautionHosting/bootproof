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

/// Block-device / volume layout, built entirely in-process from sysfs +
/// /proc/self/mounts (no external lsblk).
///
/// One line per block device, in (major, minor) order:
/// `NAME  SIZE(bytes)  TYPE  FSTYPE  MOUNTPOINT`.
///
/// - NAME comes from the kernel's canonical block name. SIZE comes from
///   /proc/partitions (1024-byte blocks), which covers whole disks and
///   partitions uniformly.
/// - TYPE is grounded, not inferred from a superblock probe: `part` for a
///   partition (a device with no sysfs `range` attribute), `crypt` for a
///   dm-crypt target (dm/uuid `CRYPT-*`), else `disk`.
/// - FSTYPE/MOUNTPOINT come from /proc/self/mounts. The mount source may be a
///   path (e.g. `/dev/mapper/home`), which is canonicalized to a canonical
///   block name before matching. Only devices actually mounted report a
///   filesystem type; we do not probe superblocks of unmounted devices.
fn disk_summary() -> Vec<String> {
    let devdir = std::path::Path::new("/sys/dev/block");
    let entries: Vec<std::path::PathBuf> = match devdir.read_dir() {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        // /sys/dev/block unavailable (unusual container): fall back to the
        // kernel's raw partition table, as before.
        Err(_) => {
            return match std::fs::read_to_string("/proc/partitions") {
                Ok(s) => s.lines().skip(2).map(str::to_string).collect(),
                Err(_) => Vec::new(),
            };
        }
    };

    // (major, minor) -> size in bytes, from the kernel's partition table.
    // /proc/partitions gives 1024-byte block counts for every device, whole
    // disk and partition alike, which is the uniform authoritative source.
    let mut size_of: std::collections::HashMap<(u32, u32), u64> =
        std::collections::HashMap::new();
    if let Ok(p) = std::fs::read_to_string("/proc/partitions") {
        for line in p.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 3 {
                if let (Ok(m), Ok(mi), Ok(b)) =
                    (f[0].parse(), f[1].parse(), f[2].parse::<u64>())
                {
                    size_of.insert((m, mi), b * 1024);
                }
            }
        }
    }

    // (major, minor) -> canonical block name. RAM (ram*) and loopback (loop*)
    // devices are excluded: the storage summary is about block storage, and
    // the tree's real_storage_lines() guard assumes they are not listed.
    let mut keyed: Vec<(u32, u32, String)> = Vec::new();
    for p in &entries {
        let dev = match p.file_name().and_then(|x| x.to_str()) {
            Some(d) => d.to_string(),
            None => continue,
        };
        let Ok(link) = std::fs::read_link(p) else { continue };
        let name = match link.file_name().and_then(|x| x.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if name.starts_with("ram") || name.starts_with("loop") {
            continue;
        }
        let (major, minor): (u32, u32) = match dev.split_once(':') {
            Some((a, b)) => match (a.parse(), b.parse()) {
                (Ok(m), Ok(n)) => (m, n),
                _ => continue,
            },
            None => continue,
        };
        keyed.push((major, minor, name));
    }
    keyed.sort_by_key(|(maj, min, _)| (*maj, *min));

    // canonical block name -> (major, minor), for resolving mount paths.
    let mut name_to_key: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    for (major, minor, name) in &keyed {
        name_to_key.insert(name.clone(), (*major, *minor));
    }

    // (major, minor) -> (fstype, mountpoint) from the kernel's mount table.
    let mut mounts: std::collections::HashMap<(u32, u32), (String, String)> =
        std::collections::HashMap::new();
    if let Ok(m) = std::fs::read_to_string("/proc/self/mounts") {
        for line in m.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 {
                continue;
            }
            // The device field is a path (e.g. /dev/mapper/home, /dev/nvme0n1p1).
            // Canonicalize it to resolve symlinks down to a canonical block name.
            let dev = f[0];
            if !dev.starts_with('/') {
                continue;
            }
            let Ok(resolved) = std::fs::canonicalize(dev) else { continue };
            let Some(name) = resolved.file_name().and_then(|x| x.to_str()) else {
                continue;
            };
            if let Some(&k) = name_to_key.get(name) {
                mounts.insert(k, (f[2].to_string(), f[1].to_string()));
            }
        }
    }

    let mut out = Vec::new();
    for (major, minor, name) in &keyed {
        let bytes = size_of.get(&(*major, *minor)).copied().unwrap_or(0);

        // Whole-disk vs partition: the kernel exposes the `range` attribute
        // only on whole disks (e.g. nvme0n1/range = "0"); partitions have no
        // range file. This is authoritative and avoids any name guessing.
        let is_part = !std::path::PathBuf::from(format!("/sys/block/{name}/range")).exists();

        let crypt = name.starts_with("dm-")
            && std::fs::read_to_string(format!("/sys/block/{name}/dm/uuid"))
                .map(|u| u.trim().starts_with("CRYPT-"))
                .unwrap_or(false);

        let typ = if crypt { "crypt" } else if is_part { "part" } else { "disk" };

        let (fstype, mp) = mounts
            .get(&(*major, *minor))
            .cloned()
            .unwrap_or_default();

        out.push(
            format!("{name:<16} {bytes:>18}  {typ:<4}  {fstype:<11}  {mp}").trim_end().to_string(),
        );
    }
    out
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
