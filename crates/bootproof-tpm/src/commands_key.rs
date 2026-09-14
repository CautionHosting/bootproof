//! Key and attestation commands for the `tpm2` channel. These use an ECC P-256
//! signing key created with **empty auth and no auth policy**, so that Quote /
//! Sign / ReadPublic can all be issued with NO auth session (tag 0x8001).
//!
//! Wire formats follow TPM 2.0 Part 2/3. All multi-byte fields are big-endian.
//! `TPM2B_*` is always a `u16` size prefix followed by that many bytes.

use crate::commands::PcrSelection;
use crate::constants::{alg, cc, st, GENERATED_VALUE};
use crate::conn::{Command, Tpm};
use crate::error::{Error, Result};
use digest::Digest;
use sha2::Sha256;

fn read_u16(b: &[u8], o: usize) -> Result<u16> {
    if b.len() < o + 2 {
        return Err(Error::Malformed("truncated u16".into()));
    }
    Ok(u16::from_be_bytes([b[o], b[o + 1]]))
}
fn read_u32(b: &[u8], o: usize) -> Result<u32> {
    if b.len() < o + 4 {
        return Err(Error::Malformed("truncated u32".into()));
    }
    Ok(u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]))
}
/// Read a `TPM2B_*` at offset: returns (size, body slice, next offset).
fn read_tpm2b(b: &[u8], o: usize) -> Result<(usize, &[u8], usize)> {
    let size = read_u16(b, o)? as usize;
    if b.len() < o + 2 + size {
        return Err(Error::Malformed("truncated TPM2B".into()));
    }
    Ok((size, &b[o + 2..o + 2 + size], o + 2 + size))
}

/// A transient key handle plus the marshalled `TPMT_PUBLIC` and `name`.
#[derive(Debug, Clone)]
pub struct Key {
    pub handle: u32,
    /// Raw `TPMT_PUBLIC` bytes (as returned by CreatePrimary / ReadPublic).
    pub public: Vec<u8>,
    /// The key's `name` (TPM2B_NAME buffer, i.e. the digest bytes).
    pub name: Vec<u8>,
}

/// Parsed TPM2_Quote result.
#[derive(Debug, Clone)]
pub struct Quote {
    /// The full `TPMS_ATTEST` bytes (starting with the GENERATED_VALUE magic).
    pub attestation: Vec<u8>,
    /// ECDSA signature `h` (r).
    pub sig_h: Vec<u8>,
    /// ECDSA signature `t` (s).
    pub sig_t: Vec<u8>,
    /// The PCR selection the quote covers (echoed in the attestation).
    pub pcr_select: Vec<u8>,
    /// The PCR digest from the attestation.
    pub pcr_digest: Vec<u8>,
}

/// objectAttributes for an ECC P-256 signing key with empty auth and no
/// auth policy: fixedTPM(0x2) | fixedParent(0x10) | sensitiveDataOrigin(0x20)
/// | userWithAuth(0x40) | restricted(0x10000) | signEncrypt(0x40000).
/// Standard TCG `TPMA_OBJECT` bit values (verified against upstream
/// tpm2-tss and the TCG spec).
const OBJ_ATTR_SIGN: u32 = 0x0005_0072;

/// Build the `TPMT_PUBLIC` template for an ECC P-256 signing key (empty auth,
/// empty unique point -- the TPM generates the key).
///
/// Layout (standard TCG): type | nameAlg | attributes | policy | symmetric
/// (NULL, 2 bytes) | scheme | hashAlg | curveID | kdf | unique. A restricted
/// signing key requires symmetric = TPM_ALG_NULL.
pub fn build_ecc_sign_template() -> Vec<u8> {
    build_ecc_sign_policy_template(&[])
}

/// Like `build_ecc_sign_template` but with a non-empty `authPolicy`: the
/// `TPM2B_DIGEST` policy digest the key requires at *usage* time (Quote,
/// Sign). The ref model `TPM2_CreatePrimary` does NOT compute or check a
/// policy at creation — `PublicAttributesValidation` only enforces
/// `authPolicy.size == nameAlg digest size` (32 for SHA256). The policy
/// session is compared against this field at usage time
/// (`CheckPolicyAuthSession`: session `policyDigest ==` the key's `authPolicy`),
/// so the caller bakes the digest here and reproduces the policy in a fresh
/// policy session when using the key. `auth_policy` must be 32 bytes for a
/// SHA256 nameAlg.
pub fn build_ecc_sign_policy_template(auth_policy: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    // type
    b.extend_from_slice(&alg::ECC.to_be_bytes());
    // nameAlg
    b.extend_from_slice(&alg::SHA256.to_be_bytes());
    // objectAttributes
    b.extend_from_slice(&OBJ_ATTR_SIGN.to_be_bytes());
    // authPolicy: TPM2B_DIGEST
    b.extend_from_slice(&(auth_policy.len() as u16).to_be_bytes());
    b.extend_from_slice(auth_policy);
    // symmetric: NULL (a restricted signing key requires NULL symmetric)
    b.extend_from_slice(&alg::NULL.to_be_bytes());
    // parameters: TPMS_ALG_ECC_PARMS
    //   scheme: TPMT_ECC_SCHEME { scheme = ECDSA, hashAlg = SHA256 }
    b.extend_from_slice(&alg::ECDSA.to_be_bytes());
    b.extend_from_slice(&alg::SHA256.to_be_bytes());
    //   curveID = NIST P-256
    b.extend_from_slice(&alg::EC_P256.to_be_bytes());
    //   kdf: TPMT_KDF_SCHEME { scheme = NULL }
    b.extend_from_slice(&alg::NULL.to_be_bytes());
    // unique: TPMS_ECC_POINT { x: TPM2B (size 0), y: TPM2B (size 0) }
    b.extend_from_slice(&0u16.to_be_bytes()); // x.size = 0
    b.extend_from_slice(&0u16.to_be_bytes()); // y.size = 0
    b
}

/// Build the `TPM2B_SENSITIVE_CREATE` value (the `TPMS_SENSITIVE_CREATE` body)
/// for an ECC signing key with empty auth.
///
/// Modern spec (verified against tss2 4.1.3 `Tss2_MU` marshalling): the body
/// is `userAuth (TPM2B_AUTH, size 0) || data (TPM2B_SENSITIVE_DATA, size 0)`
/// = `0000 0000` (4 bytes). The `sensitiveType` field present in pre-1.35
/// specs was dropped and must NOT be emitted.
pub fn build_ecc_sign_sensitive() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0u16.to_be_bytes()); // userAuth.size = 0
    b.extend_from_slice(&0u16.to_be_bytes()); // data.size = 0
    b
}

impl Tpm {
    /// TPM2_CreatePrimary: create an ECC P-256 signing key in the owner
    /// hierarchy (0x40000001 = TPM_RH_OWNER, spec Part 2 Table 42) with empty
    /// auth / no policy. Returns the transient key.
    ///
    /// The firmware requires an authorization session for CreatePrimary even
    /// when the hierarchy carries no auth, so this goes through the session
    /// path (unbound empty-auth HMAC session).
    pub fn create_primary_ecc_sign(&mut self) -> Result<Key> {
        self.create_primary_ecc_sign_session(0x4000_0001, crate::session::TPM_SE_HMAC)
    }

    /// Create an ECC P-256 signing key in `hierarchy` using an unbound
    /// empty-auth HMAC session. Returns the created key.
    ///
    /// The session is unbound: StartAuthSession's authHandle is TPM_RH_NULL
    /// (0x40000007) even though the command it authorizes targets
    /// `hierarchy` (matching the platform tss2 C stack).
    ///
    /// NOTE: call `flush_session_pools` at connection setup (before the first
    /// StartAuthSession), as the platform tss2 C stack does.
    pub fn create_primary_ecc_sign_session(
        &mut self,
        hierarchy: u32,
        session_type: u8,
    ) -> Result<Key> {
        let session = self.start_auth_session(0x4000_0007, session_type)?;
        let sensitive = build_ecc_sign_sensitive();
        let public = build_ecc_sign_template();
        let (rc, body) =
            self.call_create_primary_with_session(hierarchy, &session, &sensitive, &public)?;
        // Release the session immediately (the platform C stack flushes each
        // session after its command); leaking them exhausts the pool (0x0903).
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        parse_create_primary(&body)
    }

    /// CreatePrimary with a live auth session and fully caller-supplied
    /// inSensitive / inPublic byte strings. For differential debugging against
    /// captured tpm2-tools traffic: lets each field be varied independently.
    pub fn create_primary_raw_session(
        &mut self,
        sas_auth: u32,
        session_type: u8,
        primary_handle: u32,
        in_sensitive: &[u8],
        in_public: &[u8],
    ) -> Result<u32> {
        let session = self.start_auth_session(sas_auth, session_type)?;
        let (rc, _body) =
            self.call_create_primary_with_session(primary_handle, &session, in_sensitive, in_public)?;
        let _ = self.flush_context(session.handle);
        Ok(rc)
    }

    /// Build and send a standard ECC P-256 signing-key CreatePrimary against the
    /// given hierarchy, returning the raw response code (even on failure). Used
    /// to probe which hierarchies a TPM accepts.
    pub fn create_primary_rc(&mut self, hierarchy: u32) -> Result<u32> {
        let sensitive = build_ecc_sign_sensitive();
        let public = build_ecc_sign_template();
        let mut cmd = Command::new(cc::CREATE_PRIMARY, st::NO_SESSIONS);
        cmd.push_u32(hierarchy);
        cmd.push_u16(sensitive.len() as u16); // inSensitive: TPM2B size prefix
        cmd.push_bytes(&sensitive);
        cmd.push_u16(public.len() as u16);
        cmd.push_bytes(&public);
        cmd.push_u16(0); // outsideInfo (empty)
        cmd.push_u32(0x0000_0000); // creationPCR = TPML count 0
        let resp = self.transfer(&cmd.encode())?;
        if resp.len() < 10 {
            return Err(Error::Malformed("short CreatePrimary response".into()));
        }
        Ok(u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]))
    }

    /// CreatePrimary with fully caller-supplied inSensitive / inPublic
    /// bodies (raw TPMT_* bytes, no TPM2B size prefix) and no auth session.
    /// Returns the raw response code (even on failure). Template experiments.
    pub fn create_primary_raw_tpl(
        &mut self,
        hierarchy: u32,
        in_sensitive: &[u8],
        in_public: &[u8],
    ) -> Result<u32> {
        let mut cmd = Command::new(cc::CREATE_PRIMARY, st::NO_SESSIONS);
        cmd.push_u32(hierarchy);
        cmd.push_u16(in_sensitive.len() as u16); // inSensitive: TPM2B size
        cmd.push_bytes(in_sensitive);
        cmd.push_u16(in_public.len() as u16);
        cmd.push_bytes(in_public);
        cmd.push_u16(0); // outsideInfo (empty)
        cmd.push_u32(0x0000_0000); // creationPCR = TPML count 0
        let resp = self.transfer(&cmd.encode())?;
        if resp.len() < 10 {
            return Err(Error::Malformed("short CreatePrimary response".into()));
        }
        Ok(u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]))
    }

    /// TPM2_ReadPublic: read a key's public area and name.
    pub fn read_public(&mut self, handle: u32) -> Result<Key> {
        let mut cmd = Command::new(cc::READ_PUBLIC, st::NO_SESSIONS);
        cmd.push_u32(handle);
        let (_rc, body) = self.call(&cmd)?;
        parse_read_public(&body, handle)
    }

    /// TPM2_Quote: produce an attestation over the selected PCRs.
    ///
    /// This platform's firmware requires an authorization session for Quote
    /// (0x0125 without one), so an unbound empty-auth HMAC session is
    /// attached; the cpHash entity name is the key's `Name`.
    pub fn quote(
        &mut self,
        key: &Key,
        qualifying_data: &[u8],
        selections: &[PcrSelection],
    ) -> Result<Quote> {
        let mut params = Vec::new();
        // qualifyingData: TPM2B_DATA
        params.extend_from_slice(&(qualifying_data.len() as u16).to_be_bytes());
        params.extend_from_slice(qualifying_data);
        // inScheme: TPMT_SIG_SCHEME { scheme = ECDSA, hashAlg = SHA256 }
        params.extend_from_slice(&alg::ECDSA.to_be_bytes());
        params.extend_from_slice(&alg::SHA256.to_be_bytes());
        // pcrSelect: TPML_PCR_SELECTION { count u32, selections }
        params.extend_from_slice(&(selections.len() as u32).to_be_bytes());
        for s in selections {
            params.extend_from_slice(&s.encode());
        }

        let session = self.start_auth_session(0x4000_0007, crate::session::TPM_SE_HMAC)?;
        let (rc, body) =
            self.call_with_session(cc::QUOTE as u32, &key.name, &[key.handle], &params, &session, &[])?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        parse_quote(&body)
    }

    /// TPM2_PCR_Extend: extend a PCR with a digest (no auth session).
    pub fn pcr_extend(&mut self, pcr: u32, digest: &[u8]) -> Result<()> {
        let mut cmd = Command::new(cc::PCR_EXTEND, st::NO_SESSIONS);
        cmd.push_u32(pcr);
        // data: TPM2B_DIGEST
        cmd.push_u16(digest.len() as u16);
        cmd.push_bytes(digest);
        let (_rc, _body) = self.call(&cmd)?;
        Ok(())
    }

    /// TPM2_PCR_Reset: reset a PCR to zero (no auth session). Spec: only
    /// resettable PCRs (typically 17-22) accept this; a non-resettable PCR
    /// returns TPM_RC_PCR_WRITABLE, which `call` surfaces as an error.
    pub fn pcr_reset(&mut self, pcr: u32) -> Result<()> {
        let mut cmd = Command::new(cc::PCR_RESET, st::NO_SESSIONS);
        cmd.push_u32(pcr);
        let (_rc, _body) = self.call(&cmd)?;
        Ok(())
    }

    /// TPM2_Hash: SHA256-hash `data` in `hierarchy`. Returns (digest,
    /// ticket) where ticket is the raw TPMT_TK (tag u16 | hierarchy u32 |
    /// digest TPM2B) that this platform's Sign command requires in its
    /// validation field.
    pub fn hash(&mut self, data: &[u8], hierarchy: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut cmd = Command::new(cc::HASH, st::NO_SESSIONS);
        // data: TPM2B_DIGEST
        cmd.push_u16(data.len() as u16);
        cmd.push_bytes(data);
        // hashAlg
        cmd.push_u16(alg::SHA256);
        // hierarchy
        cmd.push_u32(hierarchy);
        let (_rc, body) = self.call(&cmd)?;
        let (_dsize, digest, off) = read_tpm2b(&body, 0)?;
        // ticket: tag u16 | hierarchy u32 | digest TPM2B
        if body.len() < off + 8 {
            return Err(Error::Malformed("Hash: truncated ticket".into()));
        }
        let tsize = read_u16(&body, off + 6)? as usize;
        if body.len() < off + 8 + tsize {
            return Err(Error::Malformed("Hash: truncated ticket digest".into()));
        }
        let ticket = body[off..off + 8 + tsize].to_vec();
        Ok((digest.to_vec(), ticket))
    }

    /// TPM2_Sign: sign a SHA256 digest with an ECDSA key.
    ///
    /// The key is restricted, so per spec (TPM 2.0 Part 2, 11.3.10) the
    /// validation field carries a creation ticket (from TPM2_Hash over the
    /// signed data, in the OWNER hierarchy) in its TPMT_TK validation field,
    /// plus an authorization session. Returns the (h, t) signature
    /// components.
    pub fn sign(&mut self, key: &Key, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (digest, ticket) = self.hash(data, 0x4000_0001)?;
        let mut params = Vec::new();
        // digest: TPM2B_DIGEST
        params.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        params.extend_from_slice(&digest);
        // inScheme: TPMT_SIG_SCHEME { scheme = ECDSA, hashAlg = SHA256 }
        params.extend_from_slice(&alg::ECDSA.to_be_bytes());
        params.extend_from_slice(&alg::SHA256.to_be_bytes());
        // validation: the creation ticket from TPM2_Hash (restricted key).
        params.extend_from_slice(&ticket);

        let session = self.start_auth_session(0x4000_0007, crate::session::TPM_SE_HMAC)?;
        let (rc, body) =
            self.call_with_session(cc::SIGN as u32, &key.name, &[key.handle], &params, &session, &[])?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u16)));
        }
        parse_signature(&body)
    }
}

/// Parse a CreatePrimary response body.
///
/// Standard spec layout (CreatePrimary_fp.h): `objectHandle | outPublic
/// TPM2B_PUBLIC | creationData | creationHash | creationTicket | name`.
/// This firmware's response inserts an extra 4-byte field after the output
/// handle (observed 0x00000121), so the outPublic size prefix sits at offset
/// 8 here instead of 4. The parser locates outPublic by scanning offset 8
/// (this firmware) and 4 (spec) for a u16-size TPM2B whose content starts
/// with TPM_ALG_ECC (0x0023). The Name is nameAlg || SHA256(publicArea),
/// where publicArea excludes the TPM2B size prefix (verified: the
/// firmware's own ReadPublic name matches this exactly).
pub fn parse_create_primary(body: &[u8]) -> Result<Key> {
    let handle = read_u32(body, 0)?;
    // Find the public area: a u16-size TPM2B whose content starts with
    // TPM_ALG_ECC (0x0023), at offset 8 (this firmware's response, which
    // inserts an extra u32 after the handle) or 4 (standard spec layout).
    let pub_off = [8usize, 4]
        .iter()
        .copied()
        .find(|&o| {
            if body.len() < o + 4 {
                return false;
            }
            let size = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
            body.len() >= o + 2 + size && body[o + 2] == 0x00 && body[o + 3] == 0x23
        })
        .ok_or_else(|| Error::Malformed("CreatePrimary: public area not found".into()))?;
    let (_psize, public, mut o) = read_tpm2b(body, pub_off)?;

    // This firmware's response: handle | extra u32 | public | creationData
    // | creationHash | ticket | extra | name. The Name is nameAlg ||
    // SHA256(publicArea), where publicArea excludes the TPM2B size prefix
    // (verified: the firmware's own ReadPublic name matches this exactly).
    if pub_off == 8 {
        if public.len() < 4 {
            return Err(Error::Malformed(
                "CreatePrimary: public area too short for name".into(),
            ));
        }
        let mut name = public[2..4].to_vec();
        name.extend_from_slice(&Sha256::digest(&public));
        return Ok(Key {
            handle,
            public: public.to_vec(),
            name,
        });
    }

    // Standard: walk the trailing size-prefixed fields until the name
    // (content starts with 0x000B = SHA256 nameAlg). A "size" that overruns
    // the buffer is a creation ticket (tag u16 | hierarchy u32 | digest TPM2B).
    // If the walk runs off the end, derive nameAlg || SHA256(public).
    let name = loop {
        if body.len() < o + 2 {
            let name_alg = if public.len() >= 2 {
                public[..2].to_vec()
            } else {
                return Err(Error::Malformed(
                    "CreatePrimary: public area too short for name".into(),
                ));
            };
            let mut name = name_alg.clone();
            name.extend_from_slice(&Sha256::digest(public));
            break name;
        }
        let size = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
        if body.len() >= o + 2 + size && size >= 2 && body[o + 2] == 0x00 && body[o + 3] == 0x0B {
            break body[o + 2..o + 2 + size].to_vec();
        }
        if size > body.len() - o {
            if body.len() < o + 8 {
                return Err(Error::Malformed("CreatePrimary: truncated ticket".into()));
            }
            let dsize = u16::from_be_bytes([body[o + 6], body[o + 7]]) as usize;
            if body.len() < o + 8 + dsize {
                return Err(Error::Malformed("CreatePrimary: truncated ticket digest".into()));
            }
            o += 8 + dsize;
            continue;
        }
        o += 2 + size;
    };
    Ok(Key {
        handle,
        public: public.to_vec(),
        name,
    })
}

/// Parse a ReadPublic response body.
pub fn parse_read_public(body: &[u8], handle: u32) -> Result<Key> {
    // outPublic: TPM2B_PUBLIC { size, TPMT_PUBLIC }
    let (_psize, public, off) = read_tpm2b(body, 0)?;
    // name: TPM2B_NAME
    let (_nsize, name, _off2) = read_tpm2b(body, off)?;
    Ok(Key {
        handle,
        public: public.to_vec(),
        name: name.to_vec(),
    })
}

/// Parse a Quote response body.
///
/// Two layouts are handled:
/// - standard: `TPM2B_ATTEST { u16 size, TPMS_ATTEST }` at offset 0, then
///   `{scheme u16, hashAlg u16, h TPM2B, t TPM2B}`.
/// - this firmware: a 6-byte prefix (`0000 | u16 | u16`, the last u16 is the
///   attest length) before the TPMS_ATTEST, then the same signature block,
///   followed by trailing bytes this client does not use.
/// The layout is detected by locating the TPM_MG_ATTEST magic (0xFF544347).
pub fn parse_quote(body: &[u8]) -> Result<Quote> {
    let magic = [0xFF, 0x54, 0x43, 0x47];
    let att_off = if body.len() >= 6 && body[2..6] == magic {
        2
    } else if body.len() >= 10 && body[6..10] == magic {
        6
    } else {
        return Err(Error::Malformed("Quote: attest magic not found".into()));
    };
    // Standard: u16 size immediately before the magic. Dialect: the size is
    // the u16 two bytes before the magic as well (offset 4 of the 6-byte
    // prefix in both cases the magic is at att_off and the size at att_off-2).
    if body.len() < att_off + 2 {
        return Err(Error::Malformed("Quote: truncated".into()));
    }
    let att_size = u16::from_be_bytes([body[att_off - 2], body[att_off - 1]]) as usize;
    if att_size == 0 || body.len() < att_off + att_size + 4 {
        return Err(Error::Malformed("Quote: truncated attest".into()));
    }
    let attest = &body[att_off..att_off + att_size];
    let mut off = att_off + att_size;
    let scheme = read_u16(body, off)?;
    if scheme != alg::ECDSA {
        return Err(Error::Malformed(format!(
            "unexpected signature scheme 0x{scheme:04X}"
        )));
    }
    off += 4; // scheme + hashAlg
    let (_hsize, sig_h, off2) = read_tpm2b(body, off)?;
    let (_tsize, sig_t, _off3) = read_tpm2b(body, off2)?;

    let q = parse_attestation_quote(attest)?;
    Ok(Quote {
        attestation: attest.to_vec(),
        sig_h: sig_h.to_vec(),
        sig_t: sig_t.to_vec(),
        pcr_select: q.pcr_select,
        pcr_digest: q.pcr_digest,
    })
}

/// Parse an ECDSA signature from a Sign response body.
///
/// Dialect layout: a short size-prefix (`0000 | u16 sig-block-size`) before
/// the `{scheme u16, hashAlg u16, h TPM2B, t TPM2B}` block, then trailing
/// bytes this client does not use. The block is located by its ECDSA scheme
/// marker.
pub fn parse_signature(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    for off in [0usize, 4, 6] {
        if body.len() < off + 4 {
            continue;
        }
        let scheme = u16::from_be_bytes([body[off], body[off + 1]]);
        if scheme != alg::ECDSA {
            continue;
        }
        let s = off + 4; // scheme + hashAlg
        if body.len() < s + 2 {
            continue;
        }
        let hsize = u16::from_be_bytes([body[s], body[s + 1]]) as usize;
        if body.len() < s + 2 + hsize + 2 {
            continue;
        }
        let sig_h = &body[s + 2..s + 2 + hsize];
        let to = s + 2 + hsize;
        let tsize = u16::from_be_bytes([body[to], body[to + 1]]) as usize;
        if body.len() < to + 2 + tsize {
            continue;
        }
        let sig_t = &body[to + 2..to + 2 + tsize];
        if hsize == 32 && tsize == 32 {
            return Ok((sig_h.to_vec(), sig_t.to_vec()));
        }
    }
    Err(Error::Malformed("Sign: ECDSA signature block not found".into()))
}

pub struct AttestQuote {
    pub pcr_select: Vec<u8>,
    pub pcr_digest: Vec<u8>,
}

/// Parse the TPMS_QUOTE_INFO out of a TPMS_ATTEST buffer.
///
/// TPMS_ATTEST:
///   magic u32 (0xFF544347), type u16 (0x8018), qualifiedSigner TPM2B_NAME,
///   extraData TPM2B_DATA, clockInfo TPMS_CLOCK_INFO (u64+u32+u32+u8),
///   firmwareVersion u64, then for QUOTE: pcrSelect TPML_PCR_SELECTION,
///   pcrDigest TPM2B_DIGEST.
pub fn parse_attestation_quote(attest: &[u8]) -> Result<AttestQuote> {
    if attest.len() < 4 {
        return Err(Error::Malformed("attestation too short".into()));
    }
    let magic = read_u32(attest, 0)?;
    if magic != GENERATED_VALUE {
        return Err(Error::Malformed(format!(
            "bad attestation magic 0x{magic:08X}"
        )));
    }
    let typ = read_u16(attest, 4)?;
    if typ != st::ATTEST_QUOTE {
        return Err(Error::Malformed(format!(
            "unexpected attestation type 0x{typ:04X}"
        )));
    }
    // qualifiedSigner TPM2B_NAME
    let (_qs_size, _qs, mut off) = read_tpm2b(attest, 6)?;
    // extraData TPM2B_DATA
    let (_ed_size, _ed, next) = read_tpm2b(attest, off)?;
    off = next;
    // clockInfo: u64 clock + u32 resetCount + u32 restartCount + u8 safe
    off += 8 + 4 + 4 + 1;
    // firmwareVersion u64
    off += 8;
    // TPMS_QUOTE_INFO: pcrSelect TPML_PCR_SELECTION { count u32, selection[] }
    // where each selection is {hash u16, pcrSelectSize u8, pcrSelect[size]}.
    let sel_count = read_u32(attest, off)? as usize;
    off += 4;
    let mut pcr_select = Vec::new();
    for _ in 0..sel_count {
        let _hash = read_u16(attest, off)?;
        off += 2;
        let sel_size = *attest
            .get(off)
            .ok_or_else(|| Error::Malformed("attestation truncated (pcrSelect)".into()))?
            as usize;
        if attest.len() < off + 1 + sel_size {
            return Err(Error::Malformed("attestation truncated (pcrSelect)".into()));
        }
        pcr_select.extend_from_slice(&attest[off..off + 1 + sel_size]);
        off += 1 + sel_size;
    }
    // pcrDigest TPM2B_DIGEST
    let (_d_size, pcr_digest, _off2) = read_tpm2b(attest, off)?;
    Ok(AttestQuote {
        pcr_select,
        pcr_digest: pcr_digest.to_vec(),
    })
}
