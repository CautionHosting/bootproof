//! NitroTPM attestation document via the AWS NSM vendor command.
//!
//! The hypervisor's NSM exposes a vendor TPM2 command (`0x20000001`) that
//! returns a COSE_Sign1 attestation document signed by the AWS Nitro
//! Attestation PKI, bound to a caller nonce. The request travels through a
//! scratch NV index: the caller writes the CBOR-encoded NSM request into
//! the index, the vendor command references the index, and the signed
//! response is read back from the same index. (Mirrors the
//! aws/NitroTPM-Tools reference flow.)
//!
//! Dialect wire truth (captured from the platform's own working
//! `tpm2_nvdefine -a 0x40004 -g sha256 -s 8192` through the tpm-bridge;
//! its request HMAC was recomputed locally to pin the layout):
//! - NV_DefineSpace params = TPM2B_AUTH (empty: `0000`) then
//!   TPM2B_NV_PUBLIC (u16 len) then TPMS_NV_PUBLIC.
//! - TPMS_NV_PUBLIC field order here is tag | nvIndex TPM2B | nameAlg |
//!   attributes | authPolicy TPM2B | data_size, and the tag is 0x0100
//!   (not the standard TPM2_ST_NV_PUBLIC 0x000C). The captured 14-byte
//!   public is `0100 0000 000b 00040004 0000 2000`.
//! - The NV is defined with EMPTY auth (no auth value), so every NV
//!   command is authorized by an unbound HMAC session with an empty auth
//!   value; the Owner hierarchy (also empty auth) authorizes define.
//!
//! Command layouts:
//! - NV_DefineSpace (0x012A): handle OWNER; params as above; response
//!   nvIndex u32 (a raw index, not a 0x0100xxxx handle) + response
//!   session area.
//! - NV_Write (0x0137): handle nvIndex; params = data TPM2B (<= 57 bytes),
//!   offset u16
//! - NV_Read (0x014E): handle nvIndex; params = size u16, offset u16
//! - NV_UndefineSpace (0x0122): handles OWNER, nvIndex (no auth)
//! - vendor 0x20000001: handles nvIndex (auth), nvIndex (index); one
//!   session; cpHash covers the index Name twice

use std::collections::BTreeMap;

use crate::conn::Tpm;
use crate::error::{Error, Result};
use crate::session::TPM_SE_HMAC;
use aws_nitro_enclaves_nsm_api::api as nsm_api;
use sha2::{Digest, Sha256};

const CC_NV_DEFINE_SPACE: u32 = 0x012A;
const CC_NV_UNDEF: u32 = 0x0122;
const CC_NV_WRITE: u32 = 0x0137;
const CC_NV_READ: u32 = 0x014E;
const CC_VENDOR_NSM_REQUEST: u32 = 0x2000_0001;

/// Owner hierarchy (wire value; identical in both dialects).
const OWNER: u32 = 0x4000_0001;
/// Null (unbound) handle for StartAuthSession.
const RH_NULL: u32 = 0x4000_0007;

const ALG_SHA256: u16 = 0x000B;
/// NV handle base for NV index handles in command headers.
const NV_HANDLE_BASE: u32 = 0x0100_0000;
/// Dialect TPMS_NV_PUBLIC tag (captured: 0x0100; standard is 0x000C).
const TAG_NV: u16 = 0x0100;
/// TPMA_NV: auth-read | auth-write (new TCG layout: b18 | b2 = 0x40000 | 4).
const NV_ATTRS_AUTH_RW: u32 = 0x0004_0004;
/// Scratch message-buffer size (reference uses 8 KiB: a plain attestation
/// document is ~5 KiB and each optional parameter is capped at 1 KiB).
const NV_SIZE: usize = 8192;
/// TPM2_MAX_NV_BUFFER_SIZE: the per-command NV data buffer limit.
const NV_WRITE_MAX: usize = 57;

/// A scratch NV index used as the NSM message buffer.
struct NvScratch {
    /// Full NV index handle for command headers (base | raw index).
    handle: u32,
    /// The index's auth value (empty: the dialect defines it with no auth).
    auth: Vec<u8>,
}

/// Dialect TPMS_NV_PUBLIC for an ORDINARY index:
/// tag | nvIndex (u16) | nameAlg | attributes | authPolicy (u16 len) |
/// data_size. The nvIndex is a bare u16 (0 = TPM-assigned), NOT a TPM2B:
/// the platform's explicit-index define captured as
/// `0100 0003 000b 00040004 0000 2000` (index 3, no length byte).
fn nv_public(name_alg: u16, attrs: u32, index: u32, data_size: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&TAG_NV.to_be_bytes());
    p.extend_from_slice(&(index as u16).to_be_bytes());
    p.extend_from_slice(&name_alg.to_be_bytes());
    p.extend_from_slice(&attrs.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // authPolicy (empty)
    p.extend_from_slice(&data_size.to_be_bytes()); // ORDINARY: data_size
    p
}

/// Dialect Name of an NV index: nameAlg (0x000b) || SHA256(dialect
/// TPMS_NV_PUBLIC) — 34 bytes. The NV_ReadPublic response's name field
/// is a TPM2B(0x22) carrying exactly this. NV commands carry two
/// handles, so the cpHash entity is this Name twice (pinned from the
/// platform's own NV_Write/NV_Read HMACs).
fn nv_name(index: u32) -> Vec<u8> {
    let mut n = Vec::with_capacity(34);
    n.extend_from_slice(&ALG_SHA256.to_be_bytes());
    n.extend_from_slice(&Sha256::digest(&nv_public(ALG_SHA256, NV_ATTRS_AUTH_RW, index, NV_SIZE as u16)));
    n
}

impl Tpm {
    /// Request the NitroTPM attestation document bound to `nonce`.
    ///
    /// Returns the raw COSE_Sign1 document (a CBOR-encoded
    /// `AttestationDocument` signed by the AWS Nitro Attestation PKI).
    pub fn attestation_document(
        &mut self,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
        scratch_index: u32,
    ) -> Result<Vec<u8>> {
        let request = nsm_api::Request::Attestation {
            user_data: user_data.map(Into::into),
            nonce: nonce.map(Into::into),
            public_key: public_key.map(Into::into),
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&request, &mut buf)
            .map_err(|e| Error::Other(format!("CBOR encode: {e}")))?;
        if buf.len() > NV_SIZE {
            return Err(Error::Other(format!(
                "NSM request too large: {} > {NV_SIZE}",
                buf.len()
            )));
        }

        // Persistent scratch NV (owner-defined, empty auth, 8 KiB):
        // the dialect's NV space holds only 3 indices and NV_UndefineSpace
        // is broken, so define/undefine per request is not viable.
        let nv = NvScratch {
            handle: NV_HANDLE_BASE | scratch_index,
            auth: Vec::new(),
        };
        let nv_handle = nv.handle;
        eprintln!("[nsi] using scratch NV index 0x{nv_handle:08x}");
        let result = (|| -> Result<Vec<u8>> {
            self.nv_write_all(&nv, &buf)?;
            eprintln!("[nsi] wrote {}B NSM request", buf.len());
            self.nsm_request(&nv)?;
            eprintln!("[nsi] vendor command OK");
            let data = self.nv_read_cbor_response(&nv)?;
            eprintln!("[nsi] read {}B response", data.len());
            let response: nsm_api::Response =
                ciborium::de::from_reader(data.as_slice())
                    .map_err(|e| Error::Other(format!("CBOR decode: {e}")))?;
            match response {
                nsm_api::Response::Attestation { document } => Ok(document),
                nsm_api::Response::Error(code) => {
                    Err(Error::Other(format!("NSM error response: {code:?}")))
                }
                other => Err(Error::Other(format!(
                    "unexpected NSM response: {other:?}"
                ))),
            }
        })();
        result
    }

    /// A command authorized by the Owner hierarchy (empty auth value).
    fn owner_session(
        &mut self,
        cc_code: u32,
        handles: &[u32],
        params: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
        let out =
            self.call_with_session(cc_code, &OWNER.to_be_bytes(), handles, params, &session, &[])?;
        let _ = self.flush_context(session.handle);
        Ok(out)
    }

    /// The index's CURRENT 34-byte Name via NV_ReadPublic (no auth). The
    /// dialect recomputes the Name when the NV_WRITTEN attribute flips, so
    /// the cpHash entity must be refreshed before every authorized NV
    /// command (the platform's tss2 does the same before each call).
    fn nv_current_name(&mut self, handle: u32) -> Result<Vec<u8>> {
        let mut cmd = Vec::with_capacity(14);
        cmd.extend_from_slice(&0x8001u16.to_be_bytes());
        cmd.extend_from_slice(&0u16.to_be_bytes());
        cmd.extend_from_slice(&14u16.to_be_bytes());
        cmd.extend_from_slice(&0u16.to_be_bytes()); // no auth handles
        cmd.extend_from_slice(&0x0169u16.to_be_bytes());
        cmd.extend_from_slice(&handle.to_be_bytes());
        let resp = self.transfer(&cmd)?;
        if resp.len() < 10 {
            return Err(Error::Malformed("NV_ReadPublic: short response".into()));
        }
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        // body: public_len u16 | public (14B) | name TPM2B (0x22 | 34B)
        let body = &resp[10..];
        if body.len() < 16 + 36 {
            return Err(Error::Malformed("NV_ReadPublic: truncated".into()));
        }
        let name = body[16..16 + 36].to_vec();
        Ok(name[2..].to_vec())
    }

    /// A command authorized by the scratch NV index (its auth value; the
    /// dialect's NV commands carry the index handle twice, so the cpHash
    /// entity is the 34-byte index Name twice).
    fn nv_session(&mut self, cc_code: u32, nv: &NvScratch, params: &[u8]) -> Result<(u32, Vec<u8>)> {
        let name = self.nv_current_name(nv.handle)?;
        let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
        let mut entity = Vec::with_capacity(name.len() * 2);
        entity.extend_from_slice(&name);
        entity.extend_from_slice(&name);
        let out = self.call_with_session(cc_code, &entity, &[nv.handle, nv.handle], params, &session, &nv.auth)?;
        let _ = self.flush_context(session.handle);
        Ok(out)
    }

    /// TPM2_Clear (0x0126) probe: clears the storage hierarchy and the DA
    /// failure counter (when the target hierarchy carries the
    /// lockoutClear attribute). The dialect's lockout hierarchy handle is
    /// unknown, so each candidate is tried in turn. Returns the per-handle
    /// response codes.
    pub fn tpm_clear_probe(&mut self, candidates: &[u32]) -> Result<Vec<(u32, u32)>> {
        let mut out = Vec::new();
        for &h in candidates {
            let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
            let (rc, _body) =
                self.call_with_session(0x0126, &h.to_be_bytes(), &[h], &[], &session, &[])?;
            let _ = self.flush_context(session.handle);
            eprintln!("[clear] hierarchy 0x{h:08x}: rc=0x{rc:04x}");
            out.push((h, rc));
            if rc == 0 {
                break;
            }
        }
        Ok(out)
    }

    /// NV_Read/NV_Write size probe against an existing index using the
    /// pinned [nv,nv] handle pair and Name34x2 entity (empty auth).
    /// Returns (read_rc, read_bytes, write_rc) for the given sizes.
    pub fn nv_rw_probe(
        &mut self,
        index: u32,
        read_size: u16,
        write_size: u16,
    ) -> Result<(u32, usize, u32)> {
        let handle = NV_HANDLE_BASE | index;
        let name = self.nv_current_name(handle)?;
        let entity = name.iter().chain(name.iter()).cloned().collect::<Vec<u8>>();
        let read_params = read_size.to_be_bytes().to_vec()
            .into_iter()
            .chain(0u16.to_be_bytes())
            .collect::<Vec<u8>>();
        let write_params = {
            let data = vec![0x5au8; write_size as usize];
            let mut p = Vec::new();
            p.extend_from_slice(&write_size.to_be_bytes());
            p.extend_from_slice(&data);
            p.extend_from_slice(&0u16.to_be_bytes());
            p
        };
        let handles = [handle, handle];
        let (rc_r, body) =
            self.nv_session_handles(CC_NV_READ, &entity, &handles, &read_params)?;
        let (rc_w, _b) =
            self.nv_session_handles(CC_NV_WRITE, &entity, &handles, &write_params)?;
        Ok((rc_r, body.len(), rc_w))
    }

    /// Like `nv_session` but with an explicit handle list (the dialect's
    /// NV commands carry two handles).
    fn nv_session_handles(
        &mut self,
        cc_code: u32,
        name: &[u8],
        handles: &[u32],
        params: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
        let out = self.call_with_session(cc_code, name, handles, params, &session, &[])?;
        let _ = self.flush_context(session.handle);
        Ok(out)
    }

    /// NV_DefineSpace with caller-controlled parameters (probe mode).
    /// `index` = 0 lets the TPM assign one (raw index value). Returns the
    /// raw response code even on failure, so dialect attribute layouts can
    /// be determined empirically. `auth` is the NV auth value (None = empty
    /// auth, the captured working form).
    pub fn nv_define_probe(
        &mut self,
        name_alg: u16,
        attrs: u32,
        data_size: u16,
        auth: Option<&[u8]>,
        index: u32,
    ) -> Result<(u32, Option<u32>)> {
        let public = nv_public(name_alg, attrs, index, data_size);
        let mut params = Vec::new();
        match auth {
            None => params.extend_from_slice(&0u16.to_be_bytes()), // empty TPM2B_AUTH
            Some(a) => {
                params.extend_from_slice(&(a.len() as u16).to_be_bytes());
                params.extend_from_slice(a);
            }
        }
        params.extend_from_slice(&(public.len() as u16).to_be_bytes());
        params.extend_from_slice(&public);

        let (rc, body) = self.owner_session(CC_NV_DEFINE_SPACE, &[OWNER], &params)?;
        let handle = if rc == 0 && body.len() >= 4 {
            Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        } else {
            None
        };
        Ok((rc, handle))
    }

    /// NV_DefineSpace probe that replicates the platform tpm2-tools command
    /// sequence exactly (dialect sequencing experiment):
    /// GetCap(ALGS,0,127) -> SAS -> GetCap(PROPS,0x100,0) -> GetCap(HANDLES,
    /// NV,23) -> NV_DefineSpace -> FlushContext. Uses a caller nonce (no
    /// GetRandom). Returns (rc, assigned raw index).
    pub fn nv_define_mimic(&mut self, data_size: u16) -> Result<(u32, Option<u32>)> {
        // GetCap(ALGS, subcap 0, limit 127)
        {
            let mut c = crate::conn::Command::new(crate::constants::cc::GET_CAPABILITY, crate::constants::st::NO_SESSIONS);
            c.push_u32(0);
            c.push_u32(0);
            c.push_u32(127);
            let resp = self.transfer(&c.encode())?;
            eprintln!("[mimic] getcap-algs resp {}B", resp.len());
        }
        // SAS with a caller-generated nonce (tss2 uses the OS RNG, not
        // TPM2_GetRandom).
        let mut nonce = [0u8; 32];
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (t >> ((i % 8) * 8)) as u8 ^ (i as u8).wrapping_mul(0x9e);
        }
        let session = self.start_auth_session_nonce(0x4000_0007, TPM_SE_HMAC, Some(&nonce))?;
        eprintln!("[mimic] SAS done");
        // GetCap(PROPS, 0x100, 0x7f) — byte-exact platform capture.
        {
            let mut c = crate::conn::Command::new(crate::constants::cc::GET_CAPABILITY, crate::constants::st::NO_SESSIONS);
            c.push_u32(6);
            c.push_u32(0x100);
            c.push_u32(0x7f);
            let resp = self.transfer(&c.encode())?;
            eprintln!("[mimic] getcap-props resp {}B", resp.len());
        }
        // GetCap(HANDLES, NV, 0x117) — byte-exact platform capture.
        {
            let mut c = crate::conn::Command::new(crate::constants::cc::GET_CAPABILITY, crate::constants::st::NO_SESSIONS);
            c.push_u32(1);
            c.push_u32(0x0100_0000);
            c.push_u32(0x117);
            let resp = self.transfer(&c.encode())?;
            eprintln!("[mimic] getcap-nv resp {}B", resp.len());
        }
        // NV_DefineSpace
        let public = nv_public(ALG_SHA256, NV_ATTRS_AUTH_RW, 0, data_size);
        let mut params = Vec::new();
        params.extend_from_slice(&0u16.to_be_bytes());
        params.extend_from_slice(&(public.len() as u16).to_be_bytes());
        params.extend_from_slice(&public);
        let (rc, body) = self.call_with_session(
            CC_NV_DEFINE_SPACE,
            &OWNER.to_be_bytes(),
            &[OWNER],
            &params,
            &session,
            &[],
        )?;
        let _ = self.flush_context(session.handle);
        let handle = if rc == 0 && body.len() >= 4 {
            Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        } else {
            None
        };
        eprintln!("[mimic] nvdefine rc=0x{rc:04x} handle={handle:?}");
        Ok((rc, handle))
    }

    /// Replay the platform's captured SAS + NV_DefineSpace verbatim. The
    /// define's HMAC is patched for each fresh SAS response nonce using
    /// the pinned formula HMAC(empty, cpHash || areaNonce || respNonce ||
    /// attrs). Tries the SAS both verbatim (original nonce) and with a
    /// fresh random nonce in the SAS TPM2B slot. Returns per-variant
    /// (rc_sas, rc_define).
    pub fn nv_replay(
        &mut self,
        sas: &[u8],
        define: &[u8],
        area_nonce: Option<&[u8]>,
        num_handles: usize,
    ) -> Result<Vec<(u32, u32)>> {
        let mut out = Vec::new();
        let variants: Vec<(String, Vec<u8>)> = {
            let mut fresh = sas.to_vec();
            let rnd = self.get_random(32)?;
            fresh[20..52].copy_from_slice(&rnd);
            vec![("sas-verbatim".to_string(), sas.to_vec()), ("sas-fresh-nonce".to_string(), fresh)]
        };
        for (name, sas_bytes) in variants {
            let resp = self.transfer(&sas_bytes)?;
            let rc_sas = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
            if resp.len() < 48 || rc_sas != 0 {
                eprintln!("[replay] {name}: SAS rc=0x{rc_sas:04x}");
                out.push((rc_sas, u32::MAX));
                continue;
            }
            let new_nonce = &resp[16..48];
            let mut d = define.to_vec();
            let s_off = 10 + 4 * num_handles;
            let area_off = s_off + 4;
            if let Some(an) = area_nonce {
                if an.len() == 32 {
                    d[area_off + 6..area_off + 38].copy_from_slice(an);
                }
            }
            let cc = d[6..10].to_vec();
            let handles = d[10..10 + 4 * num_handles].to_vec();
            let sesslen = u32::from_be_bytes([d[s_off], d[s_off + 1], d[s_off + 2], d[s_off + 3]]) as usize;
            let area_nonce = d[area_off + 6..area_off + 38].to_vec();
            let attrs = d[area_off + 38];
            let params = d[area_off + sesslen..].to_vec();
            // cpHash entity: hierarchy = raw handle; NV command (2 NV
            // handles) = 34B Name twice.
            let entity: Vec<u8> = if num_handles == 2 && d.len() > area_off {
                // Reconstruct the 34B name from the command is not
                // possible here; the caller passes the command already
                // built by bootproof, so the entity must be derivable:
                // for the NV write/read the name is the SHA256 of the
                // public with a 0x000b prefix. The probe is used with
                // commands whose entity we know, so take the first
                // 34-byte name from `define` if embedded... not present.
                // Fallback: recompute from the stored handles.
                let h = u32::from_be_bytes([d[10], d[11], d[12], d[13]]);
                let raw = h & 0x00ff_ffff;
                let n34 = nv_name(raw);
                n34.iter().chain(n34.iter()).cloned().collect()
            } else {
                handles
            };
            let mut cp = cc;
            cp.extend_from_slice(&entity);
            cp.extend_from_slice(&params);
            let cph = Sha256::digest(&cp);
            let mut msg = cph.to_vec();
            msg.extend_from_slice(&area_nonce);
            msg.extend_from_slice(new_nonce);
            msg.push(attrs);
            let h = crate::session::hmac_sha256(&[], &msg)?;
            let hmac_off = area_off + 41;
            d[hmac_off..hmac_off + 32].copy_from_slice(&h);
            eprintln!("[replay] {name}: SAS resp: {}", hex_dumps(&resp));
            eprintln!("[replay] {name}: patched define: {}", hex_dumps(&d));
            let resp2 = self.transfer(&d)?;
            let rc_def = u32::from_be_bytes([resp2[6], resp2[7], resp2[8], resp2[9]]);
            let sess_handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
            let _ = self.flush_context(sess_handle);
            eprintln!(
                "[replay] {name}: SAS rc=0x{rc_sas:04x} define rc=0x{rc_def:04x} resp {}B {}",
                resp2.len(),
                hex_dumps(&resp2)
            );
            out.push((rc_sas, rc_def));
        }
        Ok(out)
    }

    /// NV_UndefineSpace probe: `index` = raw NV index (owner-authorized).
    /// Tries several forms: (A) owner session immediately after SAS,
    /// (B) NO_SESSIONS, (C) owner session after an intervening NO_SESSIONS
    /// command (session-commit-delay hypothesis). Returns the raw response
    /// code of the first successful form, else the last failure.
    pub fn nv_undefine_probe(&mut self, index: u32) -> Result<u32> {
        let handle = NV_HANDLE_BASE | index;
        // (A) owner session immediately after SAS.
        let (rc, _body) = self.owner_session(CC_NV_UNDEF, &[OWNER, handle], &[])?;
        eprintln!("[undefine] index {index} A(session) rc=0x{rc:04x}");
        if rc == 0 {
            return Ok(rc);
        }
        // (B) NO_SESSIONS.
        let mut c = crate::conn::Command::new(CC_NV_UNDEF as u16, crate::constants::st::NO_SESSIONS);
        c.push_u32(OWNER);
        c.push_u32(handle);
        let resp = self.transfer(&c.encode())?;
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        eprintln!("[undefine] index {index} B(nosession) rc=0x{rc:04x}");
        if rc == 0 {
            return Ok(rc);
        }
        // (C) SAS -> GetCap (NO_SESSIONS) -> undefine with session.
        let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
        {
            let mut g = crate::conn::Command::new(crate::constants::cc::GET_CAPABILITY, crate::constants::st::NO_SESSIONS);
            g.push_u32(1);
            g.push_u32(0x0100_0000);
            g.push_u32(23);
            let _ = self.transfer(&g.encode());
        }
        let (rc, body) = self.call_with_session(
            CC_NV_UNDEF,
            &OWNER.to_be_bytes(),
            &[OWNER, handle],
            &[],
            &session,
            &[],
        )?;
        let _ = self.flush_context(session.handle);
        eprintln!("[undefine] index {index} C(session-after-getcap) rc=0x{rc:04x} body {}B", body.len());
        Ok(rc)
    }

    /// NV_UndefineSpace matrix: handle-base variants (0x01000000|idx,
    /// 0xB0000000|idx, raw idx) x session-entity variants (owner raw, NV
    /// Name). Reports every (name, rc). First success stops the scan.
    pub fn nv_undefine_matrix(&mut self, index: u32) -> Result<Vec<(String, u32)>> {
        let name = nv_name(index);
        let bases = [
            ("std0x01000000", NV_HANDLE_BASE | index),
            ("renamed0xB0000000", 0xB000_0000 | index),
            ("rawidx", index),
        ];
        let mut out = Vec::new();
        for (bname, handle) in bases {
            let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
            let (rc, _b) = self.call_with_session(
                CC_NV_UNDEF,
                &OWNER.to_be_bytes(),
                &[OWNER, handle],
                &[],
                &session,
                &[],
            )?;
            let _ = self.flush_context(session.handle);
            eprintln!("[umatrix] {bname} owner-entity rc=0x{rc:04x}");
            out.push((format!("{bname} owner-entity"), rc));
            if rc == 0 {
                return Ok(out);
            }
            let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
            let (rc, _b) = self.call_with_session(
                CC_NV_UNDEF,
                &name,
                &[OWNER, handle],
                &[],
                &session,
                &[],
            )?;
            let _ = self.flush_context(session.handle);
            eprintln!("[umatrix] {bname} nvname-entity rc=0x{rc:04x}");
            out.push((format!("{bname} nvname-entity"), rc));
            if rc == 0 {
                return Ok(out);
            }
        }
        Ok(out)
    }

    /// NV_DefineSpace form experiment: tries several session/no-session
    /// variants against a free index. Returns the first successful form's
    /// (name, rc, raw index), else (last name, last rc, None).
    pub fn nv_define_forms(
        &mut self,
        data_size: u16,
    ) -> Result<(String, u32, Option<u32>)> {
        let public = nv_public(ALG_SHA256, NV_ATTRS_AUTH_RW, 0, data_size);
        let mut params = Vec::new();
        params.extend_from_slice(&0u16.to_be_bytes());
        params.extend_from_slice(&(public.len() as u16).to_be_bytes());
        params.extend_from_slice(&public);

        // Form D: NO_SESSIONS (no auth at all).
        let mut c = crate::conn::Command::new(CC_NV_DEFINE_SPACE as u16, crate::constants::st::NO_SESSIONS);
        c.push_u32(OWNER);
        c.push_bytes(&params);
        let resp = self.transfer(&c.encode())?;
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        eprintln!(
            "[forms] D(nosession) rc=0x{rc:04x} resp {}B {}",
            resp.len(),
            hex_dumps(&resp)
        );
        if rc == 0 {
            return Ok(("D".into(), rc, idx_of(&resp)));
        }

        // Form E: session with EMPTY hmac (size 0) + attrs 0x01.
        {
            let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
            let mut sess_area = Vec::new();
            sess_area.extend_from_slice(&session.handle.to_be_bytes());
            sess_area.extend_from_slice(&32u16.to_be_bytes());
            sess_area.extend_from_slice(&session.nonce_caller);
            sess_area.push(0x01);
            sess_area.extend_from_slice(&0u16.to_be_bytes()); // empty hmac
            let mut body = Vec::new();
            body.extend_from_slice(&OWNER.to_be_bytes());
            body.extend_from_slice(&(sess_area.len() as u32).to_be_bytes());
            body.extend_from_slice(&sess_area);
            body.extend_from_slice(&params);
            let size = (10 + body.len()) as u32;
            let mut cmd = Vec::new();
            cmd.extend_from_slice(&crate::constants::st::SESSIONS.to_be_bytes());
            cmd.extend_from_slice(&size.to_be_bytes());
            cmd.extend_from_slice(&CC_NV_DEFINE_SPACE.to_be_bytes());
            cmd.extend_from_slice(&body);
            let resp = self.transfer(&cmd)?;
            let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
            eprintln!(
                "[forms] E(empty-hmac) rc=0x{rc:04x} resp {}B {}",
                resp.len(),
                hex_dumps(&resp)
            );
            let _ = self.flush_context(session.handle);
            if rc == 0 {
                return Ok(("E".into(), rc, idx_of(&resp)));
            }
        }

        // Form F: session with empty hmac (size 0) + attrs 0x00.
        {
            let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
            let mut sess_area = Vec::new();
            sess_area.extend_from_slice(&session.handle.to_be_bytes());
            sess_area.extend_from_slice(&32u16.to_be_bytes());
            sess_area.extend_from_slice(&session.nonce_caller);
            sess_area.push(0x00);
            sess_area.extend_from_slice(&0u16.to_be_bytes());
            let mut body = Vec::new();
            body.extend_from_slice(&OWNER.to_be_bytes());
            body.extend_from_slice(&(sess_area.len() as u32).to_be_bytes());
            body.extend_from_slice(&sess_area);
            body.extend_from_slice(&params);
            let size = (10 + body.len()) as u32;
            let mut cmd = Vec::new();
            cmd.extend_from_slice(&crate::constants::st::SESSIONS.to_be_bytes());
            cmd.extend_from_slice(&size.to_be_bytes());
            cmd.extend_from_slice(&CC_NV_DEFINE_SPACE.to_be_bytes());
            cmd.extend_from_slice(&body);
            let resp = self.transfer(&cmd)?;
            let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
            eprintln!(
                "[forms] F(empty-hmac-attrs0) rc=0x{rc:04x} resp {}B {}",
                resp.len(),
                hex_dumps(&resp)
            );
            let _ = self.flush_context(session.handle);
            if rc == 0 {
                return Ok(("F".into(), rc, idx_of(&resp)));
            }
        }

        // Form G: the standard captured form (real empty-key HMAC) -
        // included to reconfirm the baseline.
        let (rc, body) = self.owner_session(CC_NV_DEFINE_SPACE, &[OWNER], &params)?;
        eprintln!(
            "[forms] G(real-hmac) rc=0x{rc:04x} body {}B {}",
            body.len(),
            hex_dumps(&body)
        );
        Ok(("G".into(), rc, if body.len() >= 4 {
            Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        } else {
            None
        }))
    }

    /// Sequence bisection: run several SAS->define sequences, each with a
    /// fresh SAS, and report the rc of each define attempt. `pre`/`mid`
    /// select which no-session commands run before / after the SAS.
    pub fn nv_seq_test(&mut self, data_size: u16) -> Result<Vec<(String, u32)>> {
        let public = nv_public(ALG_SHA256, NV_ATTRS_AUTH_RW, 0, data_size);
        let mut params = Vec::new();
        params.extend_from_slice(&0u16.to_be_bytes());
        params.extend_from_slice(&(public.len() as u16).to_be_bytes());
        params.extend_from_slice(&public);

        let mut out = Vec::new();
        for (tag, pre, mid) in [
            ("A: SAS->define", false, false),
            ("B: SAS->getcap->define", false, true),
            ("C: getcap->SAS->define", true, false),
            ("D: getcap->SAS->getcap->define", true, true),
        ] {
            if pre {
                let _ = self.getcap_nv();
            }
            let session = match self.start_auth_session(RH_NULL, TPM_SE_HMAC) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[seq] {tag} SAS failed: {e}");
                    out.push((tag.to_string(), 0xFFFF));
                    continue;
                }
            };
            if mid {
                let _ = self.getcap_nv();
            }
            let (rc, _body) = self
                .call_with_session(
                    CC_NV_DEFINE_SPACE,
                    &OWNER.to_be_bytes(),
                    &[OWNER],
                    &params,
                    &session,
                    &[],
                )
                .unwrap_or((0xEEEE, Vec::new()));
            let _ = self.flush_context(session.handle);
            eprintln!("[seq] {tag} rc=0x{rc:04x}");
            out.push((tag.to_string(), rc));
        }
        Ok(out)
    }

    fn getcap_nv(&mut self) -> Result<Vec<u32>> {
        let mut c = crate::conn::Command::new(crate::constants::cc::GET_CAPABILITY, crate::constants::st::NO_SESSIONS);
        c.push_u32(1);
        c.push_u32(0x0100_0000);
        c.push_u32(23);
        // The send itself is the probe (no-session GET_CAPABILITY); the
        // response is intentionally ignored by this bisection helper.
        let _resp = self.transfer(&c.encode())?;
        Ok(Vec::new())
    }

    /// Send a raw command (hex) verbatim and return (rc, response hex).
    pub fn raw_send(&mut self, hexcmd: &str) -> Result<(u32, String)> {
        let h = hexcmd.trim();
        if h.len() % 2 != 0 {
            return Err(crate::error::Error::Other("odd hex length".into()));
        }
        let cmd: std::result::Result<Vec<u8>, std::num::ParseIntError> = (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16))
            .collect();
        let cmd = cmd.map_err(|e| crate::error::Error::Other(format!("hex: {e}")))?;
        let resp = self.transfer(&cmd)?;
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        Ok((rc, hex_dumps(&resp)))
    }

    /// Send a sequence of raw hex commands in one process (same open),
    /// returning (rc, response hex) for each.
    pub fn raw_replay(&mut self, cmds: &[&str]) -> Result<Vec<(u32, String)>> {
        let mut out = Vec::new();
        for c in cmds {
            let (rc, resp) = self.raw_send(c)?;
            eprintln!("[replay] rc=0x{rc:04x} resp={resp}");
            out.push((rc, resp));
        }
        Ok(out)
    }

    /// TPM2_NV_Write: write `data` in <= 57-byte chunks at offset 0.
    fn nv_write_all(&mut self, nv: &NvScratch, data: &[u8]) -> Result<()> {
        let mut offset = 0u16;
        for chunk in data.chunks(NV_WRITE_MAX) {
            let mut params = Vec::new();
            params.extend_from_slice(&(chunk.len() as u16).to_be_bytes()); // TPM2B
            params.extend_from_slice(chunk);
            params.extend_from_slice(&offset.to_be_bytes());
            let (rc, _body) = self.nv_session(CC_NV_WRITE, nv, &params)?;
            if rc != 0 {
                return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
            }
            offset += chunk.len() as u16;
        }
        Ok(())
    }

    /// Read the vendor command's NSM response back from the scratch NV.
    /// Two dialect quirks: (1) the vendor command returns OK before its
    /// response write is visible, so offset 0 is polled until data appears
    /// (up to 30s); (2) NV is pre-filled with 0xFF, so "read to the end"
    /// never terminates naturally — accumulate chunks and stop as soon as
    /// the bytes decode as a complete NSM Response.
    fn nv_read_cbor_response(&mut self, nv: &NvScratch) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut offset = 0u16;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let size = (NV_SIZE - offset as usize).min(NV_WRITE_MAX) as u16;
            let mut params = Vec::new();
            params.extend_from_slice(&size.to_be_bytes());
            params.extend_from_slice(&offset.to_be_bytes());
            let (rc, body) = self.nv_session(CC_NV_READ, nv, &params)?;
            if rc != 0 {
                return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
            }
            // body: nvIndex u16 | outer u16 (2+data) | inner u16 (data len)
            //       | data | session area.
            if body.len() < 6 {
                return Err(Error::Malformed("NV_Read: short response".into()));
            }
            let inner = u16::from_be_bytes([body[4], body[5]]) as usize;
            let data = &body[6..6 + inner.min(body.len() - 6)];
            if data.is_empty() {
                // No data yet: the vendor's response write may lag behind
                // the command; poll offset 0 until it lands.
                if offset != 0 || std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }
            buf.extend_from_slice(data);
            if ciborium::de::from_reader::<nsm_api::Response, _>(buf.as_slice()).is_ok() {
                return Ok(buf);
            }
            if data.len() < size as usize {
                break;
            }
            offset += data.len() as u16;
        }
        Ok(buf)
    }

    /// The AWS NSM vendor command (`0x20000001`): two handles (NV auth, NV
    /// index) and one HMAC session carrying the index auth value. The
    /// cpHash covers the index Name twice (both handles resolve to it).
    fn nsm_request(&mut self, nv: &NvScratch) -> Result<()> {
        let name = self.nv_current_name(nv.handle)?;
        let session = self.start_auth_session(RH_NULL, TPM_SE_HMAC)?;
        let mut entity = Vec::with_capacity(name.len() * 2);
        entity.extend_from_slice(&name);
        entity.extend_from_slice(&name);
        let (rc, _body) = self.call_with_session(
            CC_VENDOR_NSM_REQUEST,
            &entity,
            &[nv.handle, nv.handle],
            &[],
            &session,
            &nv.auth,
        )?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        Ok(())
    }
}

/// The parsed, human-readable fields of a NitroTPM (AWS NSM) attestation
/// document. The document itself is a `COSE_Sign1` whose payload is a
/// CBOR-encoded map; this is that map, decoded.
#[derive(Debug, Clone)]
pub struct AttestationFacts {
    /// Module identity, e.g. `i-02a44cb68978c43af-tpm0000000000000000`.
    pub module_id: String,
    /// PCR digest algorithm name, e.g. `SHA384`.
    pub digest: String,
    /// Document timestamp in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// PCR register values keyed by index. Accepts either the `pcrs`
    /// (nsm-api struct) or `nitrotpm_pcrs` (live wire dialect) key.
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    /// The leaf attestation certificate (DER).
    pub certificate: Vec<u8>,
    /// The CA bundle (DER certs, in the document's own order).
    pub cabundle: Vec<Vec<u8>>,
    /// The caller nonce echoed by the signer (if present).
    pub nonce: Option<Vec<u8>>,
    /// Caller user data echoed by the signer (if present).
    pub user_data: Option<Vec<u8>>,
    /// The client public key (if present).
    pub public_key: Option<Vec<u8>>,
}

/// Parse a NitroTPM attestation document (the raw `COSE_Sign1` bytes
/// returned by the NSM vendor command) into its fields.
///
/// The document is `[protected, unprotected, payload, signature]`; the
/// `payload` is a CBOR-encoded map of the attestation fields. This
/// decoder is deliberately generic (it walks the payload map by key name)
/// so it tolerates the wire dialect's `nitrotpm_pcrs` key, which the
/// `nsm_api::AttestationDoc` struct (field `pcrs`) would miss.
pub fn parse_attestation_document(document: &[u8]) -> Result<AttestationFacts> {
    let cose: Vec<ciborium::Value> =
        ciborium::de::from_reader(document).map_err(|e| Error::Malformed(format!("COSE decode: {e}")))?;
    if cose.len() != 4 {
        return Err(Error::Malformed(format!(
            "COSE_Sign1: expected 4 items, got {}",
            cose.len()
        )));
    }
    let payload_bytes = match &cose[2] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => {
            return Err(Error::Malformed(
                "COSE_Sign1 payload is not a byte string".into(),
            ))
        }
    };
    let payload: ciborium::Value =
        ciborium::de::from_reader(payload_bytes.as_slice())
            .map_err(|e| Error::Malformed(format!("payload CBOR decode: {e}")))?;
    let entries = match &payload {
        ciborium::Value::Map(m) => m.clone(),
        _ => return Err(Error::Malformed("attestation payload is not a map".into())),
    };

    let mut module_id = String::new();
    let mut digest = String::new();
    let mut timestamp_ms = 0u64;
    let mut pcrs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut certificate = Vec::new();
    let mut cabundle: Vec<Vec<u8>> = Vec::new();
    let mut nonce: Option<Vec<u8>> = None;
    let mut user_data: Option<Vec<u8>> = None;
    let mut public_key: Option<Vec<u8>> = None;

    for (key, value) in entries.iter() {
        let name = match key {
            ciborium::Value::Text(t) => t.as_str(),
            _ => continue,
        };
        match name {
            "module_id" => {
                module_id = value.as_text().map(str::to_string).unwrap_or_default()
            }
            "digest" => digest = value.as_text().map(str::to_string).unwrap_or_default(),
            "timestamp" => timestamp_ms = value
                .as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .unwrap_or(0),
            "pcrs" | "nitrotpm_pcrs" => {
                if let Some(map) = value.as_map() {
                    for (idx, data) in map.iter() {
                        if let (Some(i), Some(d)) = (
                            idx.as_integer().and_then(|i| u64::try_from(i).ok()),
                            data.as_bytes(),
                        ) {
                            pcrs.insert(i as u32, d.clone());
                        }
                    }
                }
            }
            "certificate" => certificate = value.as_bytes().cloned().unwrap_or_default(),
            "cabundle" => {
                if let Some(arr) = value.as_array() {
                    for item in arr.iter() {
                        if let Some(b) = item.as_bytes() {
                            cabundle.push(b.clone());
                        }
                    }
                }
            }
            "nonce" => nonce = value.as_bytes().cloned(),
            "user_data" => user_data = value.as_bytes().cloned(),
            "public_key" => public_key = value.as_bytes().cloned(),
            _ => {}
        }
    }

    Ok(AttestationFacts {
        module_id,
        digest,
        timestamp_ms,
        pcrs,
        certificate,
        cabundle,
        nonce,
        user_data,
        public_key,
    })
}

fn hex_dumps(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn idx_of(resp: &[u8]) -> Option<u32> {
    if resp.len() >= 14 {
        Some(u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real live NitroTPM attestation document (COSE_Sign1), checked in
    // so the parser is exercised against the actual wire dialect
    // (notably the `nitrotpm_pcrs` key and the 5-cert chain).
    const LIVE_DOC: &[u8] = include_bytes!("data/nsm-live.cbor");

    #[test]
    fn parse_live_doc_fields() {
        let f = parse_attestation_document(LIVE_DOC).expect("parse live doc");
        assert_eq!(f.module_id, "i-02a44cb68978c43af-tpm0000000000000000");
        assert_eq!(f.digest, "SHA384");
        assert!(f.timestamp_ms > 0);
        // PCRs arrive under the wire dialect's `nitrotpm_pcrs` key.
        assert_eq!(f.pcrs.len(), 24);
        for i in 0..24u32 {
            assert_eq!(f.pcrs[&i].len(), 48, "PCR {i} is SHA-384");
        }
        assert_eq!(f.certificate.len(), 627);
        assert_eq!(f.cabundle.len(), 4, "chain: root, regional, zonal, instance");
        // The nonce was echoed by the signer (32 random bytes).
        assert_eq!(f.nonce.as_deref().map(|n| n.len()), Some(32));
        assert!(f.user_data.is_none());
        assert!(f.public_key.is_none());
    }

    #[test]
    fn parse_rejects_non_cose() {
        assert!(parse_attestation_document(&[0x01, 0x02, 0x03]).is_err());
    }
}
