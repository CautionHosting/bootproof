//! Policy-bound primary keys and public-area parsing.
//!
//! A `sign` key is created with a `TPM2_PolicyPCR` auth policy: the TPM
//! accepts the key's private operations (Quote, Sign) only while the live
//! PCRs still match the policy. Per the ref model (ms-tpm-20-ref
//! `src/command/EA/PolicyPCR.c`) the policy digest updates as:
//!
//! ```text
//! authPolicy = H( prev_authPolicy
//!                || TPM_CC_PolicyPCR        (0x0000017F, 4 bytes)
//!                || TPML_PCR_SELECTION      (count u32 + selections)
//!                || pcrDigest               (SINGLE combined digest =
//!                                            H(concat of the selected PCR
//!                                            values, ascending index),
//!                                            raw bytes, no size prefix) )
//! ```
//!
//! with `prev_authPolicy` empty for the first policy command. Policy commands
//! take `policySession` as a bare handle(1) and carry NO auth session
//! (NO_SESSIONS): the command attribute row has no `HANDLE_1_USER`.

use sha2::Sha256;
use digest::Digest;

use crate::commands::PcrSelection;
use crate::constants::{alg, cc, st};
use crate::conn::{Command, Tpm};
use crate::error::{Error, Result};
use crate::session::{Session, TPM_SE_HMAC, TPM_SE_POLICY};

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
    /// Wire format (TCG 2.0 Part 1, `PolicyPCR_fp.h` — confirmed against
    /// ms-tpm-20-ref): `policySession` is the command's **handle(1)** (its
    /// RC modifier is `TPM_RC_H+TPM_RC_1` = 0x0184, the failure we hit when
    /// the handle area was empty). Parameters follow in the order
    /// `pcrDigest TPM2B_DIGEST` (a SINGLE digest = the TPM-computed
    /// `H(concat of the selected PCR values, ascending index)` —
    /// `PCRComputeCurrentDigest` in the ref model), then `pcrs
    /// TPML_PCR_SELECTION`. `per_pcr` must be the selected PCR values in
    /// ascending index order (each a full digest, matching the selection's
    /// hash algorithm); we combine them into the single digest the TPM
    /// expects.
    pub fn start_policy_pcr_session(
        &mut self,
        selections: &[PcrSelection],
        per_pcr: &[(u8, Vec<u8>)],
    ) -> Result<Session> {
        // Unbound session: StartAuthSession's authHandle is TPM_RH_NULL
        // (the session is not bound to any parent key); the command's own
        // hierarchy handle is separate.
        let session = self.start_auth_session(crate::constants::rh::NULL, TPM_SE_POLICY)?;

        // pcrDigest: the single combined digest the TPM computes itself —
        // H(concat of the selected PCR values, ascending index).
        let combined = combine_pcr_digest(per_pcr);

        // params (ref-model order, PolicyPCR_fp.h): pcrDigest TPM2B_DIGEST
        // | pcrs TPML_PCR_SELECTION.
        let mut params = Vec::new();
        params.extend_from_slice(&(combined.len() as u16).to_be_bytes());
        params.extend_from_slice(&combined);
        params.extend_from_slice(&marshal_pcr_selection_list(selections));

        // PolicyPCR carries NO authorization session. The ref-model command
        // attribute row is IS_IMPLEMENTED+DECRYPT_2+ALLOW_TRIAL — no
        // HANDLE_1_USER — so `policySession` is a bare handle(1), not an auth
        // entity, and the command is sent as NO_SESSIONS (tss2
        // Esys_PolicyCommandCode passes ESYS_TR_NONE for all three session
        // slots). Putting the policy session in the auth area instead trips
        // ParseSessionBuffer's "no associated handle + no decrypt/encrypt/
        // audit" check (RC 0x0982, session(1) inconsistent attributes).
        let mut cmd = Command::new(cc::POLICY_PCR, st::NO_SESSIONS);
        cmd.push_u32(session.handle); // policySession = handle(1)
        cmd.push_bytes(&params);
        match self.call(&cmd) {
            Ok(_) => Ok(session),
            Err(e) => {
                // Release the session context: the firmware's pool is small and
                // a leaked session here starves the next CreatePrimary (0x0902).
                let _ = self.flush_context(session.handle);
                Err(e)
            }
        }
    }

    /// Create a primary ECC signing key in the OWNER hierarchy whose
    /// `authPolicy` is bound to a PCR policy: the key's private operations
    /// (Quote, Sign) are accepted only while the live PCRs still match.
    ///
    /// Per the ref model the digest is NOT computed by the TPM at creation —
    /// `TPM2_CreatePrimary` has no policy path, and `PublicAttributesValidation`
    /// only enforces `authPolicy.size == nameAlg digest size`. So we compute the
    /// digest offline (`policy_pcr_auth_policy`, proven == live in d3b), bake it
    /// into the template's `authPolicy`, and authorize CreatePrimary with a plain
    /// unbound HMAC session on the owner hierarchy. A policy session on the
    /// hierarchy would instead be checked against the hierarchy's EMPTY
    /// `authPolicy` (`CheckPolicyAuthSession`) and fail `TPM_RC_POLICY_FAIL`.
    /// The policy binds at USAGE time: the caller reproduces the policy in a
    /// fresh policy session when calling Quote/Sign.
    pub fn create_primary_sign_policy(
        &mut self,
        selections: &[PcrSelection],
        per_pcr: &[(u8, Vec<u8>)],
    ) -> Result<crate::commands_key::Key> {
        let hierarchy = crate::constants::rh::OWNER;
        let digest = policy_pcr_auth_policy(selections, per_pcr);
        let sensitive = crate::commands_key::build_ecc_sign_sensitive();
        let public = crate::commands_key::build_ecc_sign_policy_template(&digest);
        let session = self.start_auth_session(crate::constants::rh::NULL, TPM_SE_HMAC)?;
        let (rc, body) =
            self.call_create_primary_with_session(hierarchy, &session, &sensitive, &public)?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        let key = crate::commands_key::parse_create_primary(&body)?;
        // Verify the firmware stored the authPolicy in outPublic (the whole
        // point of the key: it now requires the policy digest at usage).
        let parsed = parse_public_area(&key.public)?;
        if parsed.auth_policy != digest {
            return Err(Error::Other(format!(
                "created key authPolicy is {}B, want the 32B policy digest",
                parsed.auth_policy.len()
            )));
        }
        Ok(key)
    }

    /// TPM2_PolicyGetDigest (CC 0x0189) over an existing policy session:
    /// returns the session's current policy digest. `policySession` is the
    /// command's handle(1) (`PolicyGetDigest_fp.h`: `RC_PolicyGetDigest_
    /// policySession = TPM_RC_H+TPM_RC_1`); no parameters; no auth session
    /// (NO_SESSIONS); the response is a single `TPM2B_DIGEST`.
    pub fn policy_get_digest(&mut self, session: &Session) -> Result<Vec<u8>> {
        let mut cmd = Command::new(cc::POLICY_GET_DIGEST, st::NO_SESSIONS);
        cmd.push_u32(session.handle); // policySession = handle(1)
        match self.call(&cmd) {
            Ok((_rc, body)) => {
                // policyDigest TPM2B_DIGEST: u16 size + bytes.
                if body.len() < 2 {
                    return Err(Error::Malformed("PolicyGetDigest: truncated".into()));
                }
                let sz = u16::from_be_bytes([body[0], body[1]]) as usize;
                if body.len() < 2 + sz {
                    return Err(Error::Malformed("PolicyGetDigest: truncated digest".into()));
                }
                Ok(body[2..2 + sz].to_vec())
            }
            Err(e) => {
                let _ = self.flush_context(session.handle);
                Err(e)
            }
        }
    }

    /// Read an object's public area and name raw (works for persistent NV
    /// indexes too, where the "public" data is the raw stored bytes, e.g. an
    /// X.509 EK certificate).
    pub fn read_public_raw(&mut self, handle: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut cmd = Command::new(cc::READ_PUBLIC, st::NO_SESSIONS);
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

/// The combined PCR digest the TPM computes internally for `TPM2_PolicyPCR`
/// (`PCRComputeCurrentDigest` in the ref model): `H(concat of the selected
/// PCR values, ascending index)` — the same combination the Quote's
/// `pcrValue` digest uses. `per_pcr` is sorted by index so the concatenation
/// is deterministic regardless of input order.
pub fn combine_pcr_digest(per_pcr: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut sorted: Vec<&(u8, Vec<u8>)> = per_pcr.iter().collect();
    sorted.sort_by_key(|(i, _)| *i);
    let mut h = Sha256::new();
    for (_, d) in sorted {
        h.update(d);
    }
    h.finalize().to_vec()
}

/// The expected `authPolicy` after a single `TPM2_PolicyPCR` (empty previous
/// policy). Per the ref model `TPM2_PolicyPCR` (ms-tpm-20-ref
/// src/command/EA/PolicyPCR.c) the digest updates as
/// `H( policyDigest || TPM_CC_PolicyPCR || PCRS || pcrDigest )` where `PCRS`
/// is the marshaled `TPML_PCR_SELECTION` and `pcrDigest` is the SINGLE
/// combined digest (raw bytes, no size prefix — `CryptDigestUpdate2B` hashes
/// the buffer only).
///
/// **Dialect divergence (verified against the live SEV-SNP NitroTPM):** this
/// firmware seeds a fresh policy session's `policyDigest` with a full
/// zero-filled digest buffer (32 bytes for SHA256), NOT the empty buffer the
/// reference model uses. So the "previous" contribution here is 32 zero
/// bytes. Proven byte-exact: live `PolicyGetDigest` == `H(0x00×32 || CC ||
/// TPML || combined)`. This is the value a key created under this policy
/// carries as `authPolicy`, and the value a caller must present (or
/// reproduce in a fresh policy session) to use the key.
pub fn policy_pcr_auth_policy(
    selections: &[PcrSelection],
    per_pcr: &[(u8, Vec<u8>)],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([0u8; 32]); // dialect: previous policyDigest is a zero-filled buffer
    h.update((cc::POLICY_PCR as u32).to_be_bytes());
    h.update(marshal_pcr_selection_list(selections));
    let combined = combine_pcr_digest(per_pcr);
    h.update(&combined);
    h.finalize().to_vec()
}
