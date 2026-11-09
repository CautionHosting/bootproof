//! The tpm2 channel: an AK quote over the measured PCRs, a PCR-policy-bound
//! sign key, and the slot link that binds every channel to this TPM at this
//! moment.
//!
//! Per-request flow (stateless; all keys are primary keys, no NV writes):
//! 1. Fold the slot link: `PCR_Reset(22)` then `PCR_Extend(22, H(concat
//!    other docs))` (only when other channels exist and PCR22 is exposed).
//!    On refusal the node degrades: PCR22 is dropped from the quote and the
//!    verifier reports the honest "no slot PCR on this TPM" boundary.
//! 2. Read the attested PCRs (including the folded PCR22 when it ran).
//! 3. Create the state-bound `sign` key: `PolicyPCR` over the attested set,
//!    then `CreatePrimary` authorized by that policy.
//! 4. Create the AK (signing, auth-only) and produce a Quote over the
//!    attested set with `qualifyingData == nonce[..32]` (the front 32 bytes
//!    of the 64-byte challenge).
//! 5. Read the EK certificate from NV if present (bundled as an anchor).
//!
//! The tpm2 `doc` layout (v1, big-endian):
//! ```text
//! u8     version = 1
//! TPM2B  quote_attest    (TPMS_ATTEST bytes, what the AK signed)
//! TPM2B  ak_public       (AK TPMT_PUBLIC)
//! TPM2B  sig_r           (ECDSA r, 32 B)
//! TPM2B  sig_s           (ECDSA s, 32 B)
//! TPM2B  per_pcr         (concatenated per-PCR digests, ascending index)
//! ```

use std::path::Path;

use sha2::Sha256;
use digest::Digest;

use bootproof_tpm::{PcrSelection, Tpm, constants::alg};

use crate::channel::{Channel, Collected};
use crate::wire::{B64, Evidence, KeyInfo, Keys};

/// The slot link PCR: the tpm2 channel extends it with the hash of the
/// other channels' docs before quoting, binding them to this TPM.
pub const SLOT_PCR: u8 = 22;

/// The attested PCR set: the measured-boot PCRs (0-16) plus the slot link.
pub fn attested_pcrs() -> Vec<u8> {
    let mut v: Vec<u8> = (0..=16).collect();
    v.push(SLOT_PCR);
    v
}

/// The canonical selection for both the quote and the sign key policy.
pub fn attested_selection() -> PcrSelection {
    PcrSelection::new(alg::SHA256, &attested_pcrs())
}

/// The tpm2 channel.
pub struct Tpm2 {
    device: std::path::PathBuf,
    tcp: Option<String>,
    /// The raw NV scratch index the NSM identity doc uses as its message
    /// buffer (`Some` = attempt the NSM vendor command). OPT-IN because the
    /// vendor flow WRITES the index (dialect NV holds only 3 indices and
    /// NV_UndefineSpace is broken, so the platform pre-defines one); a
    /// non-Nitro host must never touch NV for an attestation it cannot
    /// complete. A platform configures this (`with_nsm_scratch`) after
    /// defining the index; `None` keeps the channel pure-read.
    nsm_scratch: Option<u32>,
}

impl Tpm2 {
    pub fn new(device: impl Into<std::path::PathBuf>) -> Self {
        Self {
            device: device.into(),
            tcp: None,
            nsm_scratch: None,
        }
    }

    /// Enable the NSM identity doc leg: the raw NV scratch index (lower 24
    /// bits; NV_HANDLE_BASE is added by `attest.rs`) the platform has
    /// already defined with empty owner auth, 8 KiB, AUTHWRITE|OWNERWRITE.
    /// NitroTPM platforms (wardend seald) call this; other platforms never
    /// do, so the vendor command is never issued and NV is never written.
    pub fn with_nsm_scratch(mut self, index: u32) -> Self {
        self.nsm_scratch = Some(index);
        self
    }

    /// Use a swtpm over TCP (host:port) instead of the char device.
    pub fn with_tcp(mut self, addr: String) -> Self {
        self.tcp = Some(addr);
        self
    }

    fn open(&self) -> Result<Tpm, String> {
        match &self.tcp {
            Some(addr) => Tpm::connect_swtpm_tcp_started(addr),
            None => Tpm::open_started(&self.device),
        }
        .map_err(|e| format!("open tpm: {e}"))
    }
}

impl Channel for Tpm2 {
    fn name(&self) -> &'static str {
        "tpm2"
    }

    fn detect(&self) -> bool {
        self.open().is_ok()
    }

    fn collect(&self, nonce: &[u8; 64], other_docs: &[Vec<u8>]) -> Result<Collected, String> {
        let mut tpm = self.open()?;
        // The Quote binds the FRONT 32 bytes of the 64-byte challenge as
        // `qualifyingData` (byte-identical to the verifier's comparison: the
        // verifier's 32-byte challenge is the front 32 of this challenge).
        let qualifying: [u8; 32] = nonce[..32].try_into().unwrap();
        // Clear contexts left behind by earlier connections: this firmware
        // keeps sessions across process lifetimes, a live session blocks the
        // next StartAuthSession (0x0903), and it refuses
        // GetCapability(HANDLES) -- so flush the small auto-allocated ranges
        // directly.
        let _ = tpm.flush_session_pools();
        // Stale transient objects (primaries from prior runs) occupy the
        // finite context pool and starve the AK CreatePrimary (0x0902); the
        // platform tss2 stack flushes them in its preamble, so do the same.
        let _ = tpm.flush_range(0x8000_0000, 0x8000_00FF);

        // 1. Discover the PCR set this TPM actually exposes, and intersect it
        //    with the desired measured-boot set (PCRs 0-16 + slot PCR22). This
        //    adapts to TPMs with fewer PCRs (e.g. AWS NitroTPM only has 0-7).
        let all = PcrSelection::all(alg::SHA256);
        let discovered = tpm
            .pcr_read(&[all])
            .map_err(|e| format!("PCR_Read(discover): {e}"))?;
        let available = discovered
            .selection
            .map(|s| s.indices())
            .unwrap_or_default();
        let mut indices: Vec<u8> = attested_pcrs()
            .iter()
            .cloned()
            .filter(|i| available.contains(i))
            .collect();
        if indices.is_empty() {
            return Err("TPM exposes none of the attested PCRs".to_string());
        }

        // 2. Slot link: fold the other channels' docs into PCR22 so the value
        //    is deterministic and the verifier can recompute it. Reset PCR22
        //    to zero first, then extend with H(docs), so the attested value is
        //    H(0^32 || H(docs)) regardless of what PCR22 held before. Only
        //    attempt when there are other docs and the TPM exposes PCR22. If
        //    the reset or extend is refused (a locality-3-locked PCR22 on a
        //    virtual TPM, or a firmware that won't let us write the slot PCR),
        //    degrade: drop PCR22 from the quote so the verifier reports the
        //    honest "not present on this TPM" boundary instead of a value we
        //    did not set.
        let mut slot_folded = false;
        if !other_docs.is_empty() && available.contains(&SLOT_PCR) {
            let mut concat = Vec::new();
            for d in other_docs {
                concat.extend_from_slice(d);
            }
            let slot_digest = Sha256::digest(&concat);
            match tpm
                .pcr_reset(SLOT_PCR as u32)
                .and_then(|()| tpm.pcr_extend(SLOT_PCR as u32, &slot_digest))
            {
                Ok(()) => slot_folded = true,
                Err(e) => {
                    eprintln!(
                        "[attest] slot link PCR{SLOT_PCR} not writable ({e}); omitting it from the quote"
                    );
                }
            }
        }
        if !slot_folded {
            // PCR22 must not be in the quote: we did not establish a known
            // value, so attesting it would hand the verifier a number that is
            // neither our fold nor a measured boot state.
            indices.retain(|i| *i != SLOT_PCR);
        }
        let sel = PcrSelection::new(alg::SHA256, &indices);

        // 3. Read the attested PCRs (post-extend).
        let read = tpm
            .pcr_read(&[sel])
            .map_err(|e| format!("PCR_Read: {e}"))?;
        if read.values.len() != indices.len() {
            return Err(format!(
                "PCR_Read returned {} values, expected {}",
                read.values.len(),
                indices.len()
            ));
        }
        let per_pcr: Vec<(u8, Vec<u8>)> = indices
            .iter()
            .zip(read.values.iter())
            .map(|(i, v)| (*i, v.digest.clone()))
            .collect();
        // The combined digest the Quote reports: H(concat of per-PCR digests,
        // ascending index).
        let mut h = Sha256::new();
        for (_, d) in &per_pcr {
            h.update(d);
        }
        let pcr_digest = h.finalize().to_vec();

        // 4. State-bound sign key (PolicyPCR + CreatePrimary). Firmware
        //    without policy sessions (e.g. AWS NitroTPM) can't produce one;
        //    the AK quote then carries the attestation on its own.
        let sign_key = match tpm.create_primary_sign_policy(&[sel], &per_pcr) {
            Ok(k) => Some(k),
            Err(e) => {
                eprintln!("[attest] no state-bound sign key: {e}");
                None
            }
        };

        // 5. AK + Quote(qualifyingData = front 32 of the challenge).
        let ak = tpm
            .create_primary_ecc_sign()
            .map_err(|e| format!("AK CreatePrimary: {e}"))?;
        let quote = tpm
            .quote(&ak, &qualifying, &[sel])
            .map_err(|e| format!("Quote: {e}"))?;
        if quote.pcr_digest != pcr_digest {
            return Err(format!(
                "quote pcrDigest mismatch: quote={:?} computed={:?}",
                hex(&quote.pcr_digest),
                hex(&pcr_digest)
            ));
        }
        // Release the AK object handle; every attest call creates a new
        // primary and the context pool is finite.
        let _ = tpm.flush_context(ak.handle);

        // 6. EK certificate (best effort; absent on some platforms).
        //    DEFECT FIX (2026-11-09): this used `read_public_raw`, which
        //    returns the TPM2B_PUBLIC bytes of the index's *metadata*
        //    structure, not the certificate. The real EK cert lives in the
        //    NV index's data area: NV_Read_public for the declared size,
        //    NV_Read (chunked to TPM_PT_NV_BUFFER_MAX) for the bytes.
        let ek_cert = read_ek_cert(&mut tpm);

        // 6b. NSM identity document (NitroTPM only, best effort). The AWS
        //     NSM vendor command (`0x20000001`) produces a COSE_Sign1
        //     attestation document signed by the AWS Nitro attestation PKI
        //     (chains to the root already baked in bootproof-sdk). The
        //     request carries THIS run's AK public area as `public_key` and
        //     the challenge nonce: AWS thereby signs "the key that quotes
        //     on this TPM at this challenge" -- the AK binding that the NV
        //     EK cert provides on other platforms and NitroTPM lacks.
        //     Fresh per request (the nonce rides inside the signed doc), so
        //     no cache and no TTL exists to get wrong. Honest absence on
        //     every failure path (non-Nitro firmware, no scratch NV index,
        //     vendor error): the bundle simply carries no `nsm_doc` anchor
        //     and the verifier stays silent on the binding, exactly the
        //     ek_cert absent/present split.
        let nsm_doc = match self.nsm_scratch {
            Some(scratch) => match tpm.attestation_document(
                None,
                Some(qualifying.to_vec()),
                Some(ak.public.clone()),
                scratch,
            ) {
                Ok(doc) => Some(doc),
                Err(e) => {
                    eprintln!("[attest] no NSM identity doc (vendor command failed): {e}");
                    None
                }
            },
            None => None,
        };

        // The tpm2 doc.
        let mut doc = Vec::new();
        doc.push(1); // version
        push_tpm2b(&mut doc, &quote.attestation);
        push_tpm2b(&mut doc, &ak.public);
        push_tpm2b(&mut doc, &quote.sig_h);
        push_tpm2b(&mut doc, &quote.sig_t);
        let mut per_pcr_concat = Vec::new();
        for (_, d) in &per_pcr {
            per_pcr_concat.extend_from_slice(d);
        }
        push_tpm2b(&mut doc, &per_pcr_concat);

        let mut anchors = std::collections::BTreeMap::new();
        if let Some(cert) = ek_cert {
            anchors.insert("ek_cert".into(), B64::new(cert));
        }
        if let Some(doc) = nsm_doc {
            anchors.insert("nsm_doc".into(), B64::new(doc));
        }

        let evidence = Evidence {
            channel: "tpm2".into(),
            doc: B64::new(doc),
            anchors,
        };

        let keys = sign_key.as_ref().map(|sk| Keys {
            enc: None, // ECDH encrypt-to-machine: later phase
            sign: Some(KeyInfo {
                pub_: B64::new(sk.public.clone()),
                curve: "P-256".into(),
                scheme: "ecdsa-sha256".into(),
                pcr_policy: indices.clone(),
                cert_by_ek: None, // TPM2_Certify by the EK: later phase
            }),
        });

        // Release the state-bound key: only its public area is embedded in
        // the bundle (the Quote carries the AK's signature), and the
        // firmware's transient pool is finite.
        if let Some(sk) = sign_key.as_ref() {
            let _ = tpm.flush_context(sk.handle);
        }

        Ok(Collected {
            evidence,
            keys,
        })
    }
}

fn push_tpm2b(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Read the EK certificate from its NV index. Returns `Some(bytes)` ONLY
/// when the index data actually parses as an X.509 certificate (DER or
/// PEM); every other outcome (no index, no read auth, unreadable, short
/// read, non-cert bytes) is an honest `None` so the bundle reports the
/// honest absence instead of shipping a fake cert.
///
/// This is the defect fix: `NV_Read_public` answers with the index's
/// metadata (a ~34-byte `TPMT_NV_PUBLIC`), NOT the certificate bytes, so
/// reading the cert requires `NV_Read` on the index data area, chunked to
/// the TPM's `TPM_PT_NV_BUFFER_MAX`. The X.509 gate is the regression
/// tripwire: the metadata blob (or any other non-cert bytes) can never
/// again land in the bundle as `ek_cert`.
///
/// Public so a witness example (and tests) can exercise the EXACT shipped
/// read path, not a re-implementation of it.
pub fn read_ek_cert(tpm: &mut Tpm) -> Option<Vec<u8>> {
    let data = bootproof_tpm::nv::nv_read_index(tpm, bootproof_tpm::constants::rh::EK_CERT_NV)
        .map_err(|e| eprintln!("[attest] EK cert NV read failed: {e}"))
        .ok()?;
    if data.is_empty() {
        return None;
    }
    // DER first (NitroTPM stores DER), then PEM (some platforms armor it).
    use x509_parser::prelude::FromDer;
    if x509_parser::prelude::X509Certificate::from_der(&data).is_ok() {
        return Some(data);
    }
    if x509_parser::pem::parse_x509_pem(&data).is_ok() {
        return Some(data);
    }
    eprintln!(
        "[attest] EK cert index holds {} bytes that are not an X.509 \
         certificate; reporting honest absence",
        data.len()
    );
    None
}

/// Detect whether a TPM is present on the usual device path.
pub fn detect_device() -> Option<std::path::PathBuf> {
    for p in ["/dev/tpm0", "/dev/tpmrm0"] {
        if Path::new(p).exists() {
            return Some(std::path::PathBuf::from(p));
        }
    }
    None
}
