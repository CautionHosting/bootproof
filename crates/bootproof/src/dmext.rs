//! `dmext` — LUKS volume-key sealing gated on two independent hardware proofs.
//!
//! The key is a TPM2 *data object* whose `authPolicy` binds a set of PCRs (the
//! d3c path: ESAPI create/load, raw policy-session Unseal). It unseals only
//! when a fresh policy session reproduces the exact PCR digest that was live at
//! `seal` time. On top of that, unless `tpm_only`, a fresh in-process
//! `SNP_GET_EXT_REPORT` is issued and verified (VLEK signature + VLEK→ASVK→ARK
//! chain + debug-disabled + page-swap-disabled + VMPL 0 + nonce echo) *before*
//! the TPM leg is attempted. Fail-closed: no `/dev/sev-guest`, or any check
//! failing, means no key.
//!
//! The two proofs are orthogonal: the TPM leg proves *what* booted (the measured
//! PCRs match the sealed state); the SNP leg proves *where* it ran (a
//! confidential VM whose memory the platform encrypts). Together, the key is
//! released only inside an enclave that booted the exact measured image.
//!
//! The NitroTPM char device is single-open (a second `open` while one is held
//! returns EBUSY), so every connection is SEQUENCED: each phase opens, works,
//! and drops before the next opens. Transient objects are TPM-global and survive
//! a connection close (only FlushContext or a restart clears them), so an object
//! `Load`ed in the ESAPI phase is still present when the raw phase re-opens.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::wire::B64;
use bootproof_tpm::constants::{alg, cc, ht};
use bootproof_tpm::esys::{DataObject, EsysTpm, rh_std};
use bootproof_tpm::{policy_pcr_auth_policy, PcrSelection, Tpm};

/// Wire format for a sealed volume key. Persisted as JSON so it can be carried
/// out of the guest / into a key store. All byte fields are base64 via `B64`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    /// Format version (currently 1).
    pub version: u32,
    /// PCR indices bound into the policy (ascending).
    pub pcrs: Vec<u8>,
    /// The policy digest baked into the object's `authPolicy` (32B).
    pub policy_digest: B64,
    /// `TPM2B_PRIVATE` (the wrapped sensitive data / volume key).
    pub private: B64,
    /// `TPMT_PUBLIC` wire bytes (the data object's public area).
    pub public: B64,
    /// The object's `Name` (`nameAlg ‖ SHA256(public)`, 34B for SHA-256).
    pub name: B64,
}

impl SealedBlob {
    /// Load a blob from a JSON file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let blob = serde_json::from_slice(&bytes)?;
        Ok(blob)
    }

    /// Serialize to pretty JSON (for writing / display).
    pub fn to_json_pretty(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }
}

/// The single SHA-256 PCR selection covering `pcrs` (ascending).
fn selection(pcrs: &[u8]) -> PcrSelection {
    let mut sorted = pcrs.to_vec();
    sorted.sort_unstable();
    PcrSelection::new(alg::SHA256, &sorted)
}

/// Read the live values of `pcrs`, returning `[(index, digest)]` ascending.
/// Opens and drops its own (single-open) raw TPM connection, so it is safe to
/// call back-to-back with other connection phases.
fn read_live_pcrs(device: &Path, pcrs: &[u8]) -> anyhow::Result<Vec<(u8, Vec<u8>)>> {
    let mut raw = Tpm::open_started(device)?;
    let res = raw.pcr_read(&[selection(pcrs)])?;
    let mut sorted = pcrs.to_vec();
    sorted.sort_unstable();
    if res.values.len() != sorted.len() {
        anyhow::bail!(
            "pcr_read returned {} values for {} requested PCRs",
            res.values.len(),
            sorted.len()
        );
    }
    let per_pcr = sorted
        .iter()
        .zip(res.values.iter())
        .map(|(i, v)| (*i, v.digest.clone()))
        .collect();
    Ok(per_pcr)
}

/// The fail-closed SEV-SNP gate. Issues a fresh in-process report bound to a
/// random nonce and runs the shipped node's full verifier (VLEK sig + VLEK→
/// ASVK→ARK chain + debug-disabled + page-swap-disabled + VMPL 0 + nonce echo).
/// Any failure — including no `/dev/sev-guest` — is an error (no key).
fn snp_gate() -> anyhow::Result<()> {
    use crate::attest::snp::Snp;
    use crate::channel::Channel;

    let ch = Snp::new();
    if !ch.detect() {
        anyhow::bail!(
            "snp gate: /dev/sev-guest not present — refusing to release the key \
             outside a confidential VM"
        );
    }
    let mut nonce = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let col = ch.collect(&nonce, &[]).map_err(anyhow::Error::msg)?;
    let front: [u8; 32] = nonce[..32].try_into().unwrap();
    crate::verify::snp::SnpVerifier::verify_snp(&col.evidence, &front)
        .map_err(|e| anyhow::anyhow!("snp gate: {e}"))?;
    Ok(())
}

/// Phases A+B of `seal`: read the live PCRs, compute the policy digest, and
/// create the data object under the deterministic storage parent. The
/// connection is dropped at end of scope; the object is not `Load`ed, so
/// nothing persists to the TPM unless the caller follows up (e.g. with
/// `seal_persistent`'s Load + EvictControl).
fn seal_inner(device: &Path, pcrs: &[u8], data: &[u8]) -> anyhow::Result<SealedBlob> {
    // Phase A (raw): read live PCRs + compute the policy digest.
    let per_pcr = read_live_pcrs(device, pcrs)?;
    let digest = policy_pcr_auth_policy(&[selection(pcrs)], &per_pcr);
    if digest.len() != 32 {
        anyhow::bail!(
            "seal: policy digest is {} bytes, expected 32",
            digest.len()
        );
    }

    // Phase B (ESAPI): create the deterministic storage parent + the data
    // object with the digest as its authPolicy.
    let blob = {
        let mut esys = EsysTpm::open(device)?;
        esys.ensure_started()?;
        let owner = rh_std::OWNER;
        let parent = esys.create_storage_primary(owner)?;
        let obj = esys.create_data_object(parent.handle, data, &digest)?;
        // The public area must carry the 32-byte authPolicy we asked for.
        // TPMT_PUBLIC marshal: type(2) | nameAlg(2) | attributes(4) |
        // authPolicy TPM2B{ size(2), bytes } at offset 8.
        if obj.public.len() < 8 + 2 + 32 {
            anyhow::bail!(
                "seal: data object public area too short for authPolicy ({}B)",
                obj.public.len()
            );
        }
        let ap_size = u16::from_be_bytes([obj.public[8], obj.public[9]]) as usize;
        if ap_size != 32 || obj.public[10..10 + 32] != digest {
            anyhow::bail!("seal: baked authPolicy does not match the PCR policy digest");
        }
        SealedBlob {
            version: 1,
            pcrs: {
                let mut v = pcrs.to_vec();
                v.sort_unstable();
                v
            },
            policy_digest: B64::new(digest),
            private: B64::new(obj.private),
            public: B64::new(obj.public),
            name: B64::new(obj.name),
        }
    };
    Ok(blob)
}

/// Seal `data` (the volume key) under a PCR policy. Persists the `SealedBlob`
/// as JSON at `out`. The storage parent is deterministic, so it is not
/// persisted — `unseal` re-derives it via `CreatePrimary`.
pub fn seal(device: &Path, pcrs: &[u8], data: &[u8], out: &Path) -> anyhow::Result<SealedBlob> {
    if pcrs.is_empty() {
        anyhow::bail!("seal: need at least one PCR to bind");
    }
    let blob = seal_inner(device, pcrs, data)?;
    std::fs::write(out, blob.to_json_pretty()?)?;
    Ok(blob)
}

/// Seal `data` under a PCR policy AND `EvictControl` it to the persistent
/// handle `handle` (0x8100_0000..0x81FF_FFFF) — the `tpm2_evictcontrol`
/// model, so the object survives reboots and is reachable by tpm2-tools
/// under the same handle (the current home.sh uses 0x81010200 / 0x81010201).
/// The blob is still written to `out` for inspection / key-store carry-out.
///
/// Idempotency and replacement: if the handle is occupied, the object there
/// is FLUSHed and the slot is reused (matching the blank-disk re-format
/// semantics: a new format seals a new key and replaces the old object).
pub fn seal_persistent(device: &Path, pcrs: &[u8], data: &[u8], handle: u32, out: &Path) -> anyhow::Result<SealedBlob> {
    if pcrs.is_empty() {
        anyhow::bail!("seal: need at least one PCR to bind");
    }
    if !(0x8100_0000..=0x81FF_FFFF).contains(&handle) {
        anyhow::bail!(
            "seal: handle 0x{handle:08x} is not a persistent handle (0x8100_0000..0x81FF_FFFF)"
        );
    }
    // Phase C: persist the freshly created object to `handle`. Sequenced
    // connections (the NitroTPM char device is single-open), each phase
    // opens, works, drops:
    //   C1 (ESAPI): if the handle is occupied, register it as an ESYS_TR
    //      (Esys_TR_FromTPMPublic) and EvictControl to unload (persistent=0).
    //      Occupancy is detected with the raw ReadPublic (works on persistent
    //      handles directly; empty -> 0x018B NO_RESULT).
    //   C2 (ESAPI): re-derive the parent, Load the object as a transient,
    //      EvictControl transient->persistent (the loaded transient is a
    //      registered ESAPI resource, so the wrapper works).
    //   C3 (raw): ReadPublic the handle and cross-check the Name.
    let blob = seal_inner(device, pcrs, data)?;
    {
        // C1: occupant check + flush.
        {
            let mut raw = Tpm::open_started(device)?;
            let occupied = raw.read_public(handle).is_ok();
            drop(raw);
            if occupied {
                let mut esys = EsysTpm::open(device)?;
                esys.ensure_started()?;
                let tr = esys.from_tpm_public(handle)?;
                esys.evict_control(rh_std::OWNER, tr, 0)?;
            }
        }
        // C2: Load transient + EvictControl to the persistent handle (ESAPI).
        {
            let mut esys = EsysTpm::open(device)?;
            esys.ensure_started()?;
            let owner = rh_std::OWNER;
            let parent = esys.create_storage_primary(owner)?;
            let obj = DataObject {
                handle: 0,
                private: blob.private.0.clone(),
                public: blob.public.0.clone(),
                name: blob.name.0.clone(),
            };
            let loaded = esys.load_data_object(parent.handle, &obj)?;
            esys.evict_control(owner, loaded.handle, handle)?;
        }
        // C3: verify the occupant is OUR object (raw Name cross-check).
        {
            let mut raw = Tpm::open_started(device)?;
            let live = raw.read_public(handle)?;
            if live.name != blob.name.0 {
                anyhow::bail!(
                    "seal: persistent handle 0x{handle:08x} Name mismatch after evictcontrol"
                );
            }
        }
    }
    std::fs::write(out, blob.to_json_pretty()?)?;
    Ok(blob)
}

/// Re-seal one persistent object under a different PCR policy: unseal
/// `from` (PCR policy `from_pcrs`), then seal the released key to `to`
/// (PCR policy `to_pcrs`). The key bytes never leave this process.
///
/// Idempotent: if `to` already holds a persistent object, this is a no-op
/// success (a previous boot already migrated). Returns `true` when a
/// migration happened, `false` when `to` was already occupied.
pub fn migrate_persistent(
    device: &Path,
    from: u32,
    from_pcrs: &[u8],
    to: u32,
    to_pcrs: &[u8],
    tpm_only: bool,
) -> anyhow::Result<bool> {
    if from == to {
        anyhow::bail!("migrate: --from and --to must differ");
    }
    if !ht::PERSISTENT_RANGE.contains(&from) || !ht::PERSISTENT_RANGE.contains(&to) {
        anyhow::bail!("migrate: handles must be persistent (0x8100_0000..=0x81FF_FFFF)");
    }
    // Idempotency: destination already sealed by a previous boot.
    {
        let mut raw = Tpm::open_started(device)?;
        if raw.read_public(to).is_ok() {
            return Ok(false);
        }
    }
    let key = unseal_persistent_with_pcrs(device, from, from_pcrs, tpm_only)?;
    // The blob is written to /dev/null: the persistent handle IS the record,
    // and the caller never needs the JSON.
    seal_persistent(device, to_pcrs, &key, to, Path::new("/dev/null"))?;
    Ok(true)
}

/// Unseal a `SealedBlob`'s volume key. Gated on (a) the SEV-SNP proof (unless
/// `tpm_only`) and (b) the TPM PCR policy (live PCRs must reproduce the digest
/// baked at seal time). Returns the sealed `data`.
pub fn unseal(device: &Path, blob: &SealedBlob, tpm_only: bool) -> anyhow::Result<Vec<u8>> {
    // Gate 1: SEV-SNP (fail-closed), skipped under --tpm-only.
    if !tpm_only {
        snp_gate()?;
    }

    let pcrs = &blob.pcrs;

    // Gate 2, phase 1 (ESAPI): re-derive the deterministic storage parent and
    // `Load` the data object. The object lands in the TPM global transient pool
    // and survives this connection close.
    {
        let mut esys = EsysTpm::open(device)?;
        esys.ensure_started()?;
        let owner = rh_std::OWNER;
        let parent = esys.create_storage_primary(owner)?;
        let obj = DataObject {
            handle: 0,
            private: blob.private.0.clone(),
            public: blob.public.0.clone(),
            name: blob.name.0.clone(),
        };
        esys.load_data_object(parent.handle, &obj)?;
    }

    // Gate 2, phase 2 (raw): a fresh raw policy session must reproduce the
    // baked digest (from the LIVE PCRs) and the policy-authorized Unseal must
    // succeed. If PCRs drifted since seal, the session digest != the baked
    // authPolicy and the TPM rejects the Unseal — the fail-closed behavior.
    let per_pcr = read_live_pcrs(device, pcrs)?;

    let mut raw = Tpm::open_started(device)?;
    let trans = raw.get_handles(ht::TRANSIENT)?;
    let name = blob.name.0.clone();
    let mut rawh: Option<u32> = None;
    for h in &trans {
        if let Ok(k) = raw.read_public(*h) {
            if k.name == name {
                rawh = Some(*h);
                break;
            }
        }
    }
    let rawh = rawh.ok_or_else(|| {
        anyhow::anyhow!(
            "unseal: no loaded transient matches the sealed object's Name \
             ({}B, {} transients present)",
            name.len(),
            trans.len()
        )
    })?;

    let sess = raw.start_policy_pcr_session(&[selection(pcrs)], &per_pcr)?;
    let (rc, body) = raw.call_with_session(cc::UNSEAL as u32, &name, &[rawh], &[], &sess, &[])?;
    let _ = raw.flush_context(sess.handle);
    if rc != 0 {
        anyhow::bail!(
            "unseal rejected rc=0x{:04x} ({}) — PCR policy did not match the sealed state",
            rc,
            bootproof_tpm::error::rc_name(rc as u16)
        );
    }

    decode_outdata(&body)
}

/// Extract the 32-byte `authPolicy` from a marshaled `TPMT_PUBLIC` byte
/// string. The layout is: type(2) | nameAlg(2) | objectAttributes(4) |
/// authPolicy TPM2B{ size(2), bytes } — so the size prefix sits at offset 8
/// and the digest at offset 10. Fails closed unless it is exactly 32 bytes
/// (anything else means the object is not a PCR-policy data object).
fn parse_auth_policy(public: &[u8]) -> anyhow::Result<Vec<u8>> {
    if public.len() < 8 + 2 + 32 {
        anyhow::bail!(
            "authPolicy: public area too short ({}B), expected >= {}",
            public.len(),
            8 + 2 + 32
        );
    }
    let ap_size = u16::from_be_bytes([public[8], public[9]]) as usize;
    if ap_size != 32 {
        anyhow::bail!(
            "authPolicy: {} bytes, expected 32 (not a PCR-policy data object)",
            ap_size
        );
    }
    Ok(public[10..10 + 32].to_vec())
}

/// Read a persistent object's `Name` and `authPolicy` (32B) via ReadPublic.
/// The Name is the Unseal command's cpHash entity; the authPolicy is the
/// policyPCR digest baked at seal time.
fn read_object_policy(device: &Path, handle: u32) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut raw = Tpm::open_started(device)?;
    let k = raw.read_public(handle)?;
    let ap = parse_auth_policy(&k.public)
        .map_err(|e| anyhow::anyhow!("unseal 0x{handle:08x}: {e}"))?;
    Ok((k.name.clone(), ap))
}

/// Unseal a persistent-handle data object given its sealed PCR selection.
/// This is the pure-Rust equivalent of
/// `tpm2_unseal -c <handle> -p pcr:sha256:<list> -o <keyfile>`: it re-derives
/// the policy digest from the LIVE PCRs over `pcrs` and the policy-authorized
/// Unseal must succeed. PCR drift → `rc=0x099d` (fail-closed, no key).
/// Returns the sealed volume key.
pub fn unseal_persistent_with_pcrs(
    device: &Path,
    handle: u32,
    pcrs: &[u8],
    tpm_only: bool,
) -> anyhow::Result<Vec<u8>> {
    if pcrs.is_empty() {
        anyhow::bail!("unseal: need at least one PCR to bind");
    }
    if !ht::PERSISTENT_RANGE.contains(&handle) {
        anyhow::bail!(
            "unseal: handle 0x{handle:08x} is not a persistent handle (0x8100_0000..0x81FF_FFFF)"
        );
    }
    // Gate 1: SEV-SNP (fail-closed), skipped under --tpm-only.
    if !tpm_only {
        snp_gate()?;
    }

    // Read the object's Name (the Unseal command's cpHash entity) + its
    // baked authPolicy; cross-check the PCR policy digest the caller supplied
    // matches what the object was sealed with.
    let (name, baked_ap) = read_object_policy(device, handle)?;
    // The caller's PCR list must reproduce the baked policy digest from the
    // LIVE PCRs. We do NOT compare against baked_ap here (the digest is a
    // function of live PCR VALUES, which legitimately differ between seal and
    // unseal time only if PCRs drifted — which is exactly the failure we want
    // to catch). The TPM enforces it in the policy session + Unseal.

    // Gate 2, phase 1 (raw): live PCR read for the selection.
    let per_pcr = read_live_pcrs(device, pcrs)?;

    // Gate 2, phase 2 (raw): policy-PCR session + policy-authorized Unseal.
    let mut raw = Tpm::open_started(device)?;
    let sess = raw.start_policy_pcr_session(&[selection(pcrs)], &per_pcr)?;
    let (rc, body) = raw.call_with_session(cc::UNSEAL as u32, &name, &[handle], &[], &sess, &[])?;
    let _ = raw.flush_context(sess.handle);
    if rc != 0 {
        anyhow::bail!(
            "unseal rejected rc=0x{rc:04x} ({}) — PCR policy did not match the sealed state",
            bootproof_tpm::error::rc_name(rc as u16)
        );
    }
    let _ = baked_ap; // cross-check reserved; the TPM is authoritative
    decode_outdata(&body)
}

/// Decode the Unseal `outData` (the sealed `TPM2B_SENSITIVE_DATA`).
///
/// Spec form: `TPM2B_SENSITIVE_DATA { u16 size, bytes }` — the size prefix is
/// the first two bytes. This platform's firmware (StageX / NitroTPM dialect)
/// prepends an extra `u32` before the TPM2B (the same quirk as CreatePrimary),
/// so the size prefix sits at offset 4, not 0. We try the dialect offset first
/// (any body long enough to hold a 4-byte prefix + size), then the spec offset.
/// Returns the raw sealed bytes.
fn decode_outdata(body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (dsz, dstart) = if body.len() >= 4 + 2 {
        (u16::from_be_bytes([body[4], body[5]]) as usize, 6)
    } else {
        (u16::from_be_bytes([body[0], body[1]]) as usize, 2)
    };
    if body.len() < dstart + dsz {
        anyhow::bail!(
            "unseal: truncated outData ({}B body, {}B declared)",
            body.len(),
            dsz
        );
    }
    Ok(body[dstart..dstart + dsz].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn blob(pcrs: &[u8], data: &[u8]) -> SealedBlob {
        SealedBlob {
            version: 1,
            pcrs: pcrs.to_vec(),
            policy_digest: B64::new([0xab; 32]),
            private: B64::new(data),
            public: B64::new([0xcd; 64]),
            name: B64::new([0xef; 34]),
        }
    }

    /// serde round-trip: serialize to JSON, parse back, fields identical.
    #[test]
    fn sealed_blob_serde_roundtrip() {
        let b = blob(&[5, 7], b"stagex-dmext-d4-testkey-v1");
        let json = b.to_json_pretty().unwrap();
        let back: SealedBlob = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, b);
    }

    /// The JSON is valid UTF-8, human-inspectable, and round-trips through
    /// serde_json::Value without loss (the on-disk / key-store form).
    #[test]
    fn sealed_blob_json_is_valid_and_inspectable() {
        let b = blob(&[5, 7, 9], b"key-bytes");
        let json = b.to_json_pretty().unwrap();
        let _ = std::str::from_utf8(&json).expect("json must be valid utf-8");
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["pcrs"][0], 5);
        assert_eq!(v["pcrs"][2], 9);
        // base64 field decodes back to the exact bytes
        let priv64 = v["private"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(priv64).unwrap();
        assert_eq!(decoded, b"key-bytes");
    }

    /// `selection` sorts ascending and packs the PCR bits into the 3-byte
    /// `pcr_select` (byte i holds PCRs 8i..8i+7, bit i%8). Input [9,5,7] ->
    /// ascending [5,7,9]; bits: 5 -> b0 bit5 (0x20), 7 -> b0 bit7 (0x80),
    /// 9 -> b1 bit1 (0x02). So pcr_select = [0xA0, 0x02, 0x00], hash = SHA-256.
    #[test]
    fn selection_sorts_and_packs_bits() {
        let sel = selection(&[9, 5, 7]);
        assert_eq!(sel.hash, alg::SHA256);
        assert_eq!(sel.pcr_select, [0xA0, 0x02, 0x00]);
    }

    /// A single high PCR (>= 16) lands in byte 2. PCR 20 -> byte2 bit4 (0x10).
    #[test]
    fn selection_high_pcr_byte2() {
        let sel = selection(&[20]);
        assert_eq!(sel.pcr_select, [0x00, 0x00, 0x10]);
    }

    /// Dialect outData: a 4-byte prefix + {u16 size, bytes}. The size prefix is
    /// at offset 4, data at offset 6. A 26-byte key -> size 0x001a.
    #[test]
    fn decode_outdata_dialect_prefix() {
        let key: Vec<u8> = b"stagex-dmext-d4-testkey-v1".to_vec(); // 26B
        assert_eq!(key.len(), 26);
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8, 0, 0, 0]); // the extra u32
        body.extend_from_slice(&(26u16).to_be_bytes()); // size at offset 4
        body.extend_from_slice(&key); // data at offset 6
        assert_eq!(decode_outdata(&body).unwrap(), key);
    }

    /// A 32-byte (real LUKS volume key size) key through the dialect path.
    #[test]
    fn decode_outdata_32b_key() {
        let key = [0x5a; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8, 0, 0, 0]);
        body.extend_from_slice(&(32u16).to_be_bytes());
        body.extend_from_slice(&key);
        assert_eq!(decode_outdata(&body).unwrap(), key.to_vec());
    }

    /// Spec form (no 4-byte prefix, body shorter than 6): size at offset 0.
    #[test]
    fn decode_outdata_spec_small_body() {
        let key: Vec<u8> = vec![1, 2, 3];
        let mut body = Vec::new();
        body.extend_from_slice(&(3u16).to_be_bytes()); // size at offset 0
        body.extend_from_slice(&key);
        // body.len() == 5 < 6 -> spec path
        assert_eq!(decode_outdata(&body).unwrap(), key);
    }

    /// Truncation: declared size larger than the body -> error (fail-closed).
    #[test]
    fn decode_outdata_truncated_is_error() {
        // dialect prefix declares size 26 but only 4 data bytes present
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8, 0, 0, 0]);
        body.extend_from_slice(&(26u16).to_be_bytes());
        body.extend_from_slice(&[0u8; 4]);
        assert!(decode_outdata(&body).is_err());
    }

    /// A marshaled TPMT_PUBLIC with a 32-byte authPolicy at the canonical
    /// offsets: type(2)|nameAlg(2)|attrs(4)|size(2)=0x0020|digest(32).
    #[test]
    fn parse_auth_policy_canonical() {
        let mut pub_ = Vec::new();
        pub_.extend_from_slice(&0x0008u16.to_be_bytes()); // type KEYEDHASH
        pub_.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg SHA256
        pub_.extend_from_slice(&0u32.to_be_bytes()); // attributes
        pub_.extend_from_slice(&(32u16).to_be_bytes()); // authPolicy size
        pub_.extend_from_slice(&[0x5a; 32]); // the digest
        assert_eq!(parse_auth_policy(&pub_).unwrap(), vec![0x5a; 32]);
    }

    /// A public area with an EMPTY authPolicy (an auth-value object, not a
    /// PCR-policy object) must be rejected (fail-closed). Here the empty
    /// policy makes the area shorter than the minimum, so it is caught by the
    /// length check; the point is that it is REJECTED either way.
    #[test]
    fn parse_auth_policy_rejects_empty_policy() {
        let mut pub_ = Vec::new();
        pub_.extend_from_slice(&0x0008u16.to_be_bytes());
        pub_.extend_from_slice(&0x000Bu16.to_be_bytes());
        pub_.extend_from_slice(&0u32.to_be_bytes());
        pub_.extend_from_slice(&(0u16).to_be_bytes()); // empty authPolicy
        assert!(parse_auth_policy(&pub_).is_err());
    }

    /// A truncated public area (shorter than the minimum) is rejected.
    #[test]
    fn parse_auth_policy_rejects_short_public() {
        let pub_ = vec![0u8; 8 + 2 + 31]; // 1 byte short
        assert!(parse_auth_policy(&pub_).is_err());
    }

    /// A non-32-byte policy (e.g. a 16-byte SHA-1 policy) is rejected: our
    /// data objects are always SHA-256 PCR policies.
    #[test]
    fn parse_auth_policy_rejects_wrong_length() {
        let mut pub_ = Vec::new();
        pub_.extend_from_slice(&0u16.to_be_bytes());
        pub_.extend_from_slice(&0u16.to_be_bytes());
        pub_.extend_from_slice(&0u32.to_be_bytes());
        pub_.extend_from_slice(&(16u16).to_be_bytes());
        pub_.extend_from_slice(&[0u8; 16 + 16]); // pad so len >= 42
        let e = parse_auth_policy(&pub_).unwrap_err().to_string();
        assert!(e.contains("16 bytes"), "{e}");
    }

    /// The persistent-handle range check: the two production handles and the
    /// boundaries pass; a transient, NV, or hierarchy handle fails.
    #[test]
    fn persistent_range_checks() {
        use bootproof_tpm::constants::ht;
        assert!(ht::PERSISTENT_RANGE.contains(&0x8101_0200)); // seed (home.sh)
        assert!(ht::PERSISTENT_RANGE.contains(&0x8101_0201)); // full (home.sh)
        assert!(ht::PERSISTENT_RANGE.contains(&0x8100_0000)); // range start
        assert!(ht::PERSISTENT_RANGE.contains(&0x81FF_FFFF)); // range end
        assert!(!ht::PERSISTENT_RANGE.contains(&0x8000_0000)); // transient
        assert!(!ht::PERSISTENT_RANGE.contains(&0xB000_0000)); // NV
        assert!(!ht::PERSISTENT_RANGE.contains(&0x4000_0001)); // owner hierarchy
        assert!(!ht::PERSISTENT_RANGE.contains(&0x8200_0000)); // loaded metadata
    }
}
