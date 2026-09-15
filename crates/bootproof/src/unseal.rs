//! `unseal` — pure-Rust LUKS -> dm-crypt -> ext4 -> mount, gated on dual
//! hardware attestation (in-process SEV-SNP + TPM2 PCR policy).
//!
//! No `cryptsetup`, no `mount`, no `losetup` binaries. The on-disk format is
//! the standard LUKS2 layout (cryptsetup-compatible: a user can open the same
//! volume by hand with `cryptsetup luksOpen --key-file <keyfile> <disk>`), and
//! the dm-crypt table line is the standard kernel `crypt` target line:
//!
//!     params = <cipher_spec> <hex(master_key)> <iv_offset> <dev> \
//!              <data_offset_sectors> [allow_discards] [1 sector_size:<bytes>]
//!
//! verified against both the live kernel's accepted line (dm-crypt v1.29.0)
//! and cryptsetup 2.8.7's own table construction (lib/libdevmapper.c).
//!
//! The LUKS2 header parse, argon2id PBKDF, anti-forensic re-merge, and the
//! keyslot AES-XTS decrypt are `luks-core` (pure RustCrypto, cryptsetup-oracle
//! tested). The dm-crypt device is `devicemapper` (stratis, pure Rust). The
//! kernel performs the live-volume AES-XTS; we only recover the master key
//! once and hand it to the `crypt` target.

use std::fs::File;
use std::path::Path;
use std::time::Duration;

use devicemapper::{DM, DevId, DmName, DmOptions, DmUuid};
use rustix::mount::{mount, MountFlags};

use crate::dmext::{self, SealedBlob};

/// A LUKS2 keyslot argon2id at the pinned cost (t=4, m=512000, p=nproc) takes
/// well under a second; the master-key digest verification adds a PBKDF2. A
/// 30 s budget is generous and bounds a pathological header.
const UNLOCK_BUDGET: Duration = Duration::from_secs(30);

/// dm-crypt target line params for a LUKS2 `crypt` segment.
///
/// `cipher` is the LUKS2 encryption string (e.g. `aes-xts-plain64`); `key` is
/// the recovered master key (hex-encoded into the line); `dev` is the backing
/// block device; `offset_bytes` is the segment data offset in BYTES (converted
/// to 512-byte sectors, matching cryptsetup's `tgt->u.crypt.offset`);
/// `sector_size` is the encryption sector size in bytes (only emitted when it
/// is not the 512-byte default); `allow_discards` is the TRIM flag (we pass
/// false: the standard `cryptsetup luksOpen` path does not enable it, and some
/// kernel/backing-store combinations misbehave with it).
fn crypt_params(cipher: &str, key: &[u8], dev: &str, offset_bytes: u64, sector_size: usize, allow_discards: bool) -> String {
    let mut s = format!(
        "{} {} 0 {dev} {}",
        cipher,
        hex_str(key),
        offset_bytes >> 9
    );
    if allow_discards {
        s.push_str(" 1");
    }
    if sector_size != 512 {
        s.push_str(&format!(" 1 sector_size:{sector_size}"));
    }
    s
}

fn hex_str(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Create the dm-crypt device, load the crypt table, and resume it, returning
/// the `/dev/mapper/<name>` path.
fn open_crypt_device(name: &str, len_sectors: u64, params: &str) -> anyhow::Result<String> {
    let dm = DM::new()?;
    let dm_name = DmName::new(name)?;
    let uuid = DmUuid::new("bootproof")?;
    dm.device_create(dm_name, Some(uuid), DmOptions::private())?;
    let id = DevId::Name(dm_name);
    dm.table_load(&id, &[(0u64, len_sectors, "crypt".to_string(), params.to_string())], DmOptions::private())?;
    // No DM_SUSPEND flag = resume: the device goes active.
    dm.device_suspend(&id, DmOptions::private())?;
    // No udev in the guest: devtmpfs already created the real `/dev/dm-N`
    // node; the `/dev/mapper/<name>` entry is normally a udev symlink job.
    // libdevmapper (cryptsetup) does this for its callers; our raw-ioctl
    // path must do it itself — a plain `symlink(2)`, same as cryptsetup's
    // `copen -> /dev/dm-0`.
    let real = format!("/dev/dm-{}", dm.device_info(&id)?.device().minor);
    let link = Path::new("/dev/mapper").join(name);
    match std::os::unix::fs::symlink(&real, &link) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&link)?;
            std::os::unix::fs::symlink(&real, &link)?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(format!("/dev/mapper/{name}"))
}

/// `mount(2)` ext4 on the device (writable, nosuid, nodev). The mount point
/// must already exist.
fn mount_ext4(dev: &str, mp: &Path) -> anyhow::Result<()> {
    let flags = MountFlags::NOSUID | MountFlags::NODEV;
    mount(dev, mp, "ext4", flags, None::<&std::ffi::CStr>)
        .map_err(|e| anyhow::anyhow!("mount(2) {dev} on {mp:?}: {e}"))
}

/// The full disk flow: dual gate -> keyfile -> LUKS2 master key -> dm-crypt ->
/// (optional) ext4 mount.
///
/// Returns the mapped device path. The master key is zeroized on drop via
/// `DecryptedPayload` (which owns it).
pub fn disk(
    device: &Path,
    blob: &SealedBlob,
    tpm_only: bool,
    disk: &Path,
    name: &str,
    mount: Option<&Path>,
) -> anyhow::Result<String> {
    // Gate 1 (SEV-SNP, unless tpm_only) + Gate 2 (TPM PCR policy) -> keyfile.
    let keyfile = dmext::unseal(device, blob, tpm_only)?;

    // LUKS2: parse header + derive the master key from the keyfile (the
    // TPM-sealed value is the LUKS passphrase/keyfile, NOT the master key).
    let file = File::open(disk)
        .map_err(|e| anyhow::anyhow!("open {disk:?} (is it a LUKS volume?): {e}"))?;
    let payload = luks::LuksVolume::unlock2_with_passphrase_within(file, &keyfile, UNLOCK_BUDGET)
        .map_err(|e| anyhow::anyhow!("luks unlock failed: {e}"))?;
    let info = payload.info();
    let key = payload.master_key();
    tracing::info!(
        "unseal: LUKS2 ok ({}-{} key {}B, sector {})",
        info.cipher_name,
        info.cipher_mode,
        info.key_bytes,
        info.sector_size
    );

    // LUKS2 data offset (the crypt segment). Re-parse the header for the
    // segment facts (cipher_spec, data offset in bytes, sector size). Read
    // ONLY the header region (hdr_size bytes), never the whole volume.
    let (cipher, seg_offset, seg_sector) = {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = File::open(disk)?;
        // First 4096 B: binary superblock; hdr_size is a big-endian u64 at offset 8.
        let mut bin = [0u8; 4096];
        f.by_ref().take(4096).read_exact(&mut bin)?;
        let hdr_size = u64::from_be_bytes(bin[8..16].try_into().unwrap()) as usize;
        let mut hdr = vec![0u8; hdr_size.max(4096)];
        f.seek(SeekFrom::Start(0))?;
        f.read_exact(&mut hdr)?;
        let h2 = luks::Luks2Header::parse(&hdr)?;
        let s = h2
            .crypt_segment()
            .ok_or_else(|| anyhow::anyhow!("no crypt segment in the LUKS2 header"))?;
        (s.encryption.clone(), s.offset, s.sector_size)
    };

    // Map length: the whole encrypted payload, in 512-byte sectors.
    let len_sectors = (payload.payload_size() + 511) / 512;
    // `cipher` is the full LUKS2 cipher string (e.g. `aes-xts-plain64`) —
    // exactly what the kernel `crypt` target expects as cipher_spec.
    let params = crypt_params(&cipher, key, disk.to_str().unwrap_or_default(), seg_offset, seg_sector, false);
    tracing::info!("unseal: dm-crypt {name} len={len_sectors} key={}B cipher={cipher}", key.len());
    let mapped = open_crypt_device(name, len_sectors, &params)?;

    if let Some(mp) = mount {
        if let Err(e) = mount_ext4(&mapped, mp) {
            // Best effort: report the mount failure but the device is open.
            eprintln!("unseal: {mapped} is open but mount on {mp:?} failed: {e}");
        } else {
            tracing::info!("unseal: mounted {mapped} on {mp:?}");
        }
    }
    Ok(mapped)
}

/// Unseal a pure value (the TPM-sealed byte blob) — the `dmext` gate, no disk.
pub fn value(device: &Path, blob: &SealedBlob, tpm_only: bool) -> anyhow::Result<Vec<u8>> {
    dmext::unseal(device, blob, tpm_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypt_params_default_512() {
        let p = crypt_params("aes-xts-plain64", &[0xab; 64], "/dev/vdb", 16_777_216, 512, false);
        assert!(p.starts_with("aes-xts-plain64 "), "{p}");
        assert!(p.contains(" 0 /dev/vdb 32768"), "{p}");
        assert!(!p.contains("sector_size"), "{p}");
        assert!(!p.contains(" 1 "), "{p}");
    }

    #[test]
    fn crypt_params_4096_sector() {
        let p = crypt_params("aes-xts-plain64", &[0xcd; 64], "/dev/nvme1n1", 16_777_216, 4096, false);
        assert!(p.contains(" 1 sector_size:4096"), "{p}");
        assert!(!p.contains("allow"), "{p}");
    }

    #[test]
    fn crypt_params_allow_discards() {
        let p = crypt_params("aes-xts-plain64", &[0xef; 64], "/dev/vdb", 16_777_216, 4096, true);
        assert!(p.contains(" 1 1 sector_size:4096"), "{p}");
    }

    #[test]
    fn offset_bytes_to_sectors() {
        assert_eq!(16_777_216u64 >> 9, 32_768u64);
        assert_eq!(0u64 >> 9, 0u64);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_str(&[0x00, 0xff, 0x10]), "00ff10");
    }
}
