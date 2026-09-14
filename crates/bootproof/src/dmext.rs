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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let col = ch.collect(&nonce, &[]).map_err(anyhow::Error::msg)?;
    crate::verify::snp::SnpVerifier::verify_snp(&col.evidence, &nonce)
        .map_err(|e| anyhow::anyhow!("snp gate: {e}"))?;
    Ok(())
}

/// Seal `data` (the volume key) under a PCR policy. Persists the `SealedBlob`
/// as JSON at `out`. The storage parent is deterministic, so it is not
/// persisted — `unseal` re-derives it via `CreatePrimary`.
pub fn seal(device: &Path, pcrs: &[u8], data: &[u8], out: &Path) -> anyhow::Result<SealedBlob> {
    if pcrs.is_empty() {
        anyhow::bail!("seal: need at least one PCR to bind");
    }

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
    // object with the digest as its authPolicy. Connection dropped at end of
    // scope; the object is not `Load`ed, so nothing persists to the TPM.
    let blob = {
        let mut esys = EsysTpm::open(device)?;
        esys.ensure_started()?;
        let _ = esys.flush_all();
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

    std::fs::write(out, blob.to_json_pretty()?)?;
    Ok(blob)
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
        let _ = esys.flush_all();
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

    // outData: TPM2B_SENSITIVE_DATA { u16 size, bytes }. This firmware
    // prepends an extra u32 before the TPM2B (same quirk as CreatePrimary), so
    // the size prefix sits at offset 4, not 0. Dialect offset first, then the
    // spec offset.
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
