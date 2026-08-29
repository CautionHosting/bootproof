//! Policy-bound primary keys and public-area parsing.
//!
//! A `sign` key is created with a `TPM2_PolicyPCR` auth policy: the TPM
//! accepts the key's private operations (Quote, Sign) only while the live
//! PCRs still match the policy. Per TPM 2.0 Part 1 the policy digest
//! updates as:
//!
//! ```text
//! authPolicy = H( prev_authPolicy
//!                || TPM_CC_PolicyPCR        (0x0000017F, 4 bytes)
//!                || TPML_PCR_SELECTION      (count u32 + selections)
//!                || TPML_PCR_DIGEST         (count u32 + each digest TPM2B,
//!                                           ascending index order) )
//! ```
//!
//! with `prev_authPolicy` empty for the first policy command.

use sha2::Sha256;
use digest::Digest;

use crate::commands::PcrSelection;
use crate::constants::{alg, cc, st};
use crate::conn::{Command, Tpm};
use crate::error::{Error, Result};
use crate::session::{Session, TPM_SE_POLICY};

/// A parsed `TPMT_PUBLIC` (ECC object).
#[derive(Debug, Clone)]
pub struct PublicArea {
    /// `nameAlg` (TPM_ALG of the Name digest).
    pub name_alg: u16,
    /// `objectAttributes` (TPMA_OBJECT).
    pub attributes: u32,
    /// `authPolicy` (the bound policy digest; empty for auth-only keys).
    pub auth_policy: Vec<u8>,
    /// Signature scheme (`TPMT_ECC_SCHEME` raw bytes).
    pub scheme_raw: Vec<u8>,
    /// `curveID` (TPM_ALG_ECC, e.g. 0x0003 = P-256).
    pub curve: u16,
    /// Unique point `x`.
    pub unique_x: Vec<u8>,
    /// Unique point `y`.
    pub unique_y: Vec<u8>,
}

fn read_u16(b: &[u8], o: usize) -> Result<u16> {
    if b.len() < o + 2 {
        return Err(Error::Malformed("public area: truncated".into()));
    }
    Ok(u16::from_be_bytes([b[o], b[o + 1]]))
}

/// Parse a `TPMT_PUBLIC` for an ECC object (standard wire layout).
pub fn parse_public_area(public: &[u8]) -> Result<PublicArea> {
    // type u16
    let typ = read_u16(public, 0)?;
    if typ != alg::ECC {
        return Err(Error::Malformed(format!(
            "public area: not an ECC object (0x{typ:04X})"
        )));
    }
    let name_alg = read_u16(public, 2)?;
    let attributes = u32::from_be_bytes([public[4], public[5], public[6], public[7]]);
    let mut off = 8;
    // authPolicy TPM2B
    let ap_size = read_u16(public, off)? as usize;
    if public.len() < off + 2 + ap_size {
        return Err(Error::Malformed("public area: truncated authPolicy".into()));
    }
    let auth_policy = public[off + 2..off + 2 + ap_size].to_vec();
    off += 2 + ap_size;
    // symmetric TPMT_SYM_DEF_OBJECT
    let sym_alg = read_u16(public, off)?;
    if sym_alg == alg::NULL {
        off += 2;
    } else {
        off += 6; // alg | keyBits | mode
    }
    // scheme TPMT_ECC_SCHEME
    let scheme_alg = read_u16(public, off)?;
    let scheme_raw = if scheme_alg == alg::NULL {
        public[off..off + 2].to_vec()
    } else {
        if public.len() < off + 4 {
            return Err(Error::Malformed("public area: truncated scheme".into()));
        }
        public[off..off + 4].to_vec()
    };
    off += if scheme_alg == alg::NULL { 2 } else { 4 };
    // curveID u16
    let curve = read_u16(public, off)?;
    off += 2;
    // kdf TPMT_KDF_SCHEME
    let kdf_alg = read_u16(public, off)?;
    off += if kdf_alg == alg::NULL { 2 } else { 4 };
    // unique TPMS_ECC_POINT { x TPM2B, y TPM2B }
    let x_size = read_u16(public, off)? as usize;
    if public.len() < off + 2 + x_size {
        return Err(Error::Malformed("public area: truncated unique.x".into()));
    }
    let unique_x = public[off + 2..off + 2 + x_size].to_vec();
    off += 2 + x_size;
    let y_size = read_u16(public, off)? as usize;
    if public.len() < off + 2 + y_size {
        return Err(Error::Malformed("public area: truncated unique.y".into()));
    }
    let unique_y = public[off + 2..off + 2 + y_size].to_vec();

    Ok(PublicArea {
        name_alg,
        attributes,
        auth_policy,
        scheme_raw,
        curve,
        unique_x,
        unique_y,
    })
}

/// Marshal a `TPML_PCR_SELECTION` (count u32 + selections).
pub fn marshal_pcr_selection_list(selections: &[PcrSelection]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(selections.len() as u32).to_be_bytes());
    for s in selections {
        b.extend_from_slice(&s.encode());
    }
    b
}

impl Tpm {
    /// Start an unbound policy session and apply a `TPM2_PolicyPCR` command
    /// over the given selection / per-PCR digests. Returns the live policy
    /// session (the caller flushes it).
    ///
    /// `per_pcr` must be the selected PCR values in ascending index order
    /// (each a full digest, matching the selection's hash algorithm).
    pub fn start_policy_pcr_session(
        &mut self,
        selections: &[PcrSelection],
        per_pcr: &[(u8, Vec<u8>)],
    ) -> Result<Session> {
        // Unbound session: StartAuthSession's authHandle is TPM_RH_NULL in
        // both the dialect and the standard (the session is not bound to any
        // parent key); the command's own hierarchy handle is separate.
        let session =
            self.start_auth_session(crate::constants::rh_std::NULL, TPM_SE_POLICY)?;

        // params: pcrSelect TPML_PCR_SELECTION | pcrs TPML_PCR_DIGEST
        let mut params = marshal_pcr_selection_list(selections);
        params.extend_from_slice(&(per_pcr.len() as u32).to_be_bytes());
        for (_idx, d) in per_pcr {
            params.extend_from_slice(&(d.len() as u16).to_be_bytes());
            params.extend_from_slice(d);
        }

        // PolicyPCR has no handles; cpHash entity is empty.
        let (rc, body) = self.call_with_session(
            cc::POLICY_PCR as u32,
            &[],
            &[],
            &params,
            &session,
            &[],
        )?;
        if rc != 0 {
            // Release the session context: the firmware's pool is small and
            // a leaked session here starves the next CreatePrimary (0x0902).
            let _ = self.flush_context(session.handle);
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        let _ = body;
        Ok(session)
    }

    /// Create a primary ECC signing key bound to a PCR policy in the OWNER
    /// hierarchy.
    ///
    /// Flow: policy session (PolicyPCR) -> CreatePrimary in the owner
    /// hierarchy authorized by that session. The key's `authPolicy` is set by
    /// the TPM to the policy digest. The session is flushed before returning.
    pub fn create_primary_sign_policy(
        &mut self,
        selections: &[PcrSelection],
        per_pcr: &[(u8, Vec<u8>)],
    ) -> Result<crate::commands_key::Key> {
        let hierarchy = if self.dialect {
            crate::constants::rh::OWNER
        } else {
            crate::constants::rh_std::OWNER
        };
        let session = self.start_policy_pcr_session(selections, per_pcr)?;
        let sensitive = crate::commands_key::build_ecc_sign_sensitive(self.dialect);
        let public = crate::commands_key::build_ecc_sign_template();
        let (rc, body) =
            self.call_create_primary_with_session(hierarchy, &session, &sensitive, &public)?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        crate::commands_key::parse_create_primary(&body)
    }

    /// Read an object's public area and name raw (works for persistent NV
    /// indexes too, where the "public" data is the raw stored bytes, e.g. an
    /// X.509 EK certificate).
    pub fn read_public_raw(&mut self, handle: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut cmd = Command::new(self.wire_cc(cc::READ_PUBLIC), st::NO_SESSIONS);
        cmd.push_u32(handle);
        let (_rc, body) = self.call(&cmd)?;
        // outPublic TPM2B | outName TPM2B
        let psize = read_u16(&body, 0)? as usize;
        if body.len() < 2 + psize + 2 {
            return Err(Error::Malformed("ReadPublic: truncated".into()));
        }
        let public = body[2..2 + psize].to_vec();
        let nsize = read_u16(&body, 2 + psize)? as usize;
        if body.len() < 4 + psize + 2 + nsize {
            return Err(Error::Malformed("ReadPublic: truncated name".into()));
        }
        let name = body[4 + psize..4 + psize + nsize].to_vec();
        Ok((public, name))
    }
}

/// The expected `authPolicy` after a single `TPM2_PolicyPCR` (empty previous
/// policy). Per TPM 2.0 Part 1 the policy digest updates as
/// `H( policyDigest || TPM_CC_PolicyPCR || pcrSelections || pcrDigests )`,
/// where `pcrDigests` is the full `TPML_PCR_DIGEST` (count u32 + each digest
/// as a TPM2B, ascending index order).
pub fn policy_pcr_auth_policy(
    selections: &[PcrSelection],
    per_pcr: &[(u8, Vec<u8>)],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update((cc::POLICY_PCR as u32).to_be_bytes());
    h.update(marshal_pcr_selection_list(selections));
    h.update(&(per_pcr.len() as u32).to_be_bytes());
    for (_, d) in per_pcr {
        h.update(&(d.len() as u16).to_be_bytes());
        h.update(d);
    }
    h.finalize().to_vec()
}
