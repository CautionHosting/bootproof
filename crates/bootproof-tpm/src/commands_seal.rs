//! TPM 2.0 sealed-data objects: `TPM2_Create` / `TPM2_Load` / `TPM2_Unseal`
//! / `TPM2_EvictControl`.
//!
//! Implements the "seal a blob behind a PCR policy, unseal it later" flow
//! used by the LUKS `/home` setup (the S15home replacement). The sealed
//! object is a `TPM_ALG_KEYEDHASH` (sealed data) object whose `authPolicy`
//! is a single `TPM2_PolicyPCR` over the selected PCRs. The parent is an
//! AES-128-CFB storage key created with `TPM2_CreatePrimary`.
//!
//! Authorization model (matches tpm2-tools `tpm2_create` / `tpm2_load` /
//! `tpm2_unseal`):
//!   - `TPM2_Create` and `TPM2_Load` authorize the *parent* storage key with
//!     an unbound empty-auth HMAC session (the parent is `userWithAuth` with
//!     an empty auth value).
//!   - `TPM2_Unseal` authorizes the *sealed object* with a policy session
//!     (the object is `adminWithPolicy`).

use sha2::{Digest, Sha256};

use crate::commands::PcrSelection;
use crate::commands_key::Key;
use crate::commands_policy::policy_pcr_auth_policy;
use crate::conn::{Tpm, HEADER_SIZE};
use crate::constants::{alg, cc, rh, rh_std, st};
use crate::error::{Error, Result};
use crate::session::{Session, TPM_SE_HMAC};

// Symmetric-mode values (CFB). The StageX firmware dialect renumbers CFB to
// 0x0043; the standard is 0x0045 (matches esys.rs SYM_MODE_CFB_*).
const SYM_MODE_CFB_STD: u16 = 0x0045;
const SYM_MODE_CFB_DIALECT: u16 = 0x0043;

// TPMA_OBJECT attribute bits (TCG Part 2, Table 33).
const OBJ_FIXED_TPM: u32 = 0x0000_0002;
const OBJ_FIXED_PARENT: u32 = 0x0000_0010;
const OBJ_SENS_DATA_ORIGIN: u32 = 0x0000_0020;
const OBJ_USER_WITH_AUTH: u32 = 0x0000_0040;
const OBJ_ADMIN_WITH_POLICY: u32 = 0x0000_0080;
const OBJ_NO_DA: u32 = 0x0000_0400;
const OBJ_RESTRICTED: u32 = 0x0001_0000;
const OBJ_DECRYPT: u32 = 0x0002_0000;

fn read_u16(b: &[u8], o: usize) -> Result<u16> {
    if b.len() < o + 2 {
        return Err(Error::Malformed("truncated u16".into()));
    }
    Ok(u16::from_be_bytes([b[o], b[o + 1]]))
}

/// Read a `TPM2B` (u16 size + octets) at offset `o`. Returns `(size, content,
/// next_offset)`.
fn read_tpm2b(b: &[u8], o: usize) -> Result<(usize, Vec<u8>, usize)> {
    let size = read_u16(b, o)? as usize;
    if b.len() < o + 2 + size {
        return Err(Error::Malformed("truncated TPM2B".into()));
    }
    Ok((size, b[o + 2..o + 2 + size].to_vec(), o + 2 + size))
}

/// Build the `TPMT_PUBLIC` body for the AES-128-CFB storage parent key.
pub fn storage_key_template(dialect: bool) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&alg::SYMCIPHER.to_be_bytes()); // type = SYMCIPHER
    b.extend_from_slice(&alg::SHA256.to_be_bytes()); // nameAlg
    let attrs = OBJ_FIXED_TPM
        | OBJ_FIXED_PARENT
        | OBJ_SENS_DATA_ORIGIN
        | OBJ_USER_WITH_AUTH
        | OBJ_RESTRICTED
        | OBJ_DECRYPT; // = 0x00030072
    b.extend_from_slice(&attrs.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // authPolicy (empty)
    // TPMT_SYM_DEF_OBJECT (TPMS_SYMCIPHER_PARMS)
    b.extend_from_slice(&alg::AES.to_be_bytes()); // symmetricAlg
    b.extend_from_slice(&0x0080u16.to_be_bytes()); // keyBits = 128
    let cfb = if dialect { SYM_MODE_CFB_DIALECT } else { SYM_MODE_CFB_STD };
    b.extend_from_slice(&cfb.to_be_bytes()); // mode
    b.extend_from_slice(&0u16.to_be_bytes()); // unique (empty)
    b
}

/// Build the `TPMT_PUBLIC` body for the sealed-data object. Its `authPolicy`
/// is the given policy digest (a single `TPM2_PolicyPCR`).
pub fn sealed_object_template(policy_digest: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&alg::KEYEDHASH.to_be_bytes()); // type = KEYEDHASH
    b.extend_from_slice(&alg::SHA256.to_be_bytes()); // nameAlg
    let attrs = OBJ_FIXED_TPM | OBJ_FIXED_PARENT | OBJ_ADMIN_WITH_POLICY | OBJ_NO_DA; // 0x00000492
    b.extend_from_slice(&attrs.to_be_bytes());
    // authPolicy: TPM2B_DIGEST
    b.extend_from_slice(&(policy_digest.len() as u16).to_be_bytes());
    b.extend_from_slice(policy_digest);
    // TPMS_KEYEDHASH_PARMS: scheme NULL only (no symmetric field on the wire)
    b.extend_from_slice(&alg::NULL.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // unique (empty)
    b
}

/// The `inSensitive` content (a `TPMS_SENSITIVE_CREATE`) for a sealed object:
/// empty `userAuth` + the sealed `data`.
fn sealed_sensitive(data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0u16.to_be_bytes()); // userAuth.size = 0
    b.extend_from_slice(&(data.len() as u16).to_be_bytes()); // data.size
    b.extend_from_slice(data);
    b
}

/// Parse a libtpms `TPM2_CreatePrimary` response body. Layout (session tag):
/// `objectHandle(4) | paramSize(4) | objectPublic TPM2B | creationData TPM2B
/// | creationHash TPM2B | creationTicket (tag u16, hierarchy u32, digest
/// TPM2B) | name TPM2B`. The creationData/creationHash/creationTicket fields
/// are a libtpms extension beyond the TCG output set; the Name is read
/// straight from the response rather than recomputed.
fn parse_create_primary_generic(body: &[u8]) -> Result<Key> {
    if body.len() < 8 {
        return Err(Error::Malformed("CreatePrimary: short body".into()));
    }
    let handle = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let mut off = 8; // skip paramSize u32 (session-tagged responses)
    let (_psize, public, next) = read_tpm2b(body, off)?;
    off = next;
    let (_cdsize, _creation_data, next) = read_tpm2b(body, off)?;
    off = next;
    let (_chsize, _creation_hash, next) = read_tpm2b(body, off)?;
    off = next;
    // creationTicket: TPM_ST tag + hierarchy + digest TPM2B.
    if body.len() < off + 6 {
        return Err(Error::Malformed("CreatePrimary: short ticket".into()));
    }
    off += 6;
    let (_tdsize, _ticket_digest, next) = read_tpm2b(body, off)?;
    off = next;
    let (_nsize, name, _next) = read_tpm2b(body, off)?;
    if name.len() < 34 {
        return Err(Error::Malformed("CreatePrimary: short name".into()));
    }
    Ok(Key {
        handle,
        public,
        name,
    })
}

impl Tpm {
    /// Create the AES-128-CFB storage parent key via `TPM2_CreatePrimary` in
    /// the owner hierarchy (standard `0x40000001`). Returns the transient key
    /// (handle + name).
    pub fn create_storage_parent(&mut self) -> Result<Key> {
        let hierarchy = if self.dialect {
            rh::OWNER
        } else {
            rh_std::OWNER
        };
        let session = self.start_auth_session(0x4000_0007, TPM_SE_HMAC)?;
        let sensitive = crate::commands_key::build_ecc_sign_sensitive(self.dialect);
        let public = storage_key_template(self.dialect);
        let (rc, body) =
            self.call_create_primary_with_session(hierarchy, &session, &sensitive, &public)?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u32 as u16)));
        }
        parse_create_primary_generic(&body)
    }

    /// `TPM2_Create`: create a sealed-data object under `parent`. The object's
    /// `authPolicy` is `policy_digest`. Returns `(name, objectPublic,
    /// privateKey)`. The parent is authorized with an unbound empty-auth HMAC
    /// session.
    pub fn create_sealed(
        &mut self,
        parent: &Key,
        data: &[u8],
        policy_digest: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let session = self.start_auth_session(0x4000_0007, TPM_SE_HMAC)?;
        let in_sensitive = sealed_sensitive(data);
        let in_public = sealed_object_template(policy_digest);

        let mut params = Vec::new();
        params.extend_from_slice(&(in_sensitive.len() as u16).to_be_bytes());
        params.extend_from_slice(&in_sensitive);
        params.extend_from_slice(&(in_public.len() as u16).to_be_bytes());
        params.extend_from_slice(&in_public);
        params.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo (empty)
        params.extend_from_slice(&0x0000_0000u32.to_be_bytes()); // creationPCR count 0

        let (rc, body) = self.call_with_session(
            self.wire_cc(cc::CREATE) as u32,
            &parent.name,
            &[parent.handle],
            &params,
            &session,
            &[], // parent auth value = empty
        )?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u32 as u16)));
        }
        // libtpms response: paramSize(4) | privateKey TPM2B | objectPublic
        // TPM2B | creationData TPM2B | creationHash TPM2B | creationTicket
        // (tag u16, hierarchy u32, digest TPM2B). No Name in the output; the
        // object Name is nameAlg || H(objectPublic).
        let (_pr, private_key, o) = read_tpm2b(&body, 4)?;
        let (_op, object_public, o) = read_tpm2b(&body, o)?;
        let (_cd, _cd_data, o) = read_tpm2b(&body, o)?;
        let (_ch, _ch_data, o) = read_tpm2b(&body, o)?;
        let dsize = read_u16(&body, o + 6)? as usize;
        let _ = o + 8 + dsize;
        let mut name = object_public[..2].to_vec();
        name.extend_from_slice(&Sha256::digest(&object_public));
        Ok((name, object_public, private_key))
    }

    /// `TPM2_Load`: load a child object (public + private) under `parent`,
    /// returning the transient object handle.
    pub fn load_object(
        &mut self,
        parent: &Key,
        object_public: &[u8],
        private_key: &[u8],
    ) -> Result<u32> {
        let session = self.start_auth_session(0x4000_0007, TPM_SE_HMAC)?;
        // libtpms Load_In order: inPrivate FIRST, then inPublic; no
        // outsideInfo in the input.
        let mut params = Vec::new();
        params.extend_from_slice(&(private_key.len() as u16).to_be_bytes());
        params.extend_from_slice(private_key);
        params.extend_from_slice(&(object_public.len() as u16).to_be_bytes());
        params.extend_from_slice(object_public);
        let (rc, body) = self.call_with_session(
            self.wire_cc(cc::LOAD) as u32,
            &parent.name,
            &[parent.handle],
            &params,
            &session,
            &[],
        )?;
        let _ = self.flush_context(session.handle);
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u32 as u16)));
        }
        if body.len() < 4 {
            return Err(Error::Malformed("Load: short response".into()));
        }
        Ok(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
    }

    /// `TPM2_Unseal`: release the sealed data of the object at `handle`
    /// (authorized by `session`), returning the data.
    pub fn unseal_obj(&mut self, handle: u32, name: &[u8], session: &Session) -> Result<Vec<u8>> {
        let (rc, body) = self.call_with_session(
            self.wire_cc(cc::UNSEAL) as u32,
            name,
            &[handle],
            &[],
            session,
            &[],
        )?;
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u32 as u16)));
        }
        // paramSize(4) | data TPM2B (no output handle on Unseal).
        let (_sz, out, _o) = read_tpm2b(&body, 4)?;
        Ok(out)
    }

    /// Read the live SHA-256 values of the selected PCRs and return
    /// `(selections, per_pcr)` where `per_pcr` is in ascending index order.
    pub fn pcr_live(&mut self, pcrs: &[u8]) -> Result<(Vec<PcrSelection>, Vec<(u8, Vec<u8>)>)> {
        let mut sorted = pcrs.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let selections = vec![PcrSelection::new(alg::SHA256, &sorted)];
        let res = self.pcr_read(&selections)?;
        let mut per_pcr = Vec::new();
        for (i, idx) in sorted.iter().enumerate() {
            let digest = res
                .values
                .get(i)
                .map(|v| v.digest.clone())
                .ok_or_else(|| Error::Malformed(format!("no value for PCR {idx}")))?;
            per_pcr.push((*idx, digest));
        }
        Ok((selections, per_pcr))
    }

    /// Seal `data` behind the PCR policy `pcrs` and persist the sealed object
    /// at `persistent`. Returns the object's Name.
    pub fn seal(&mut self, pcrs: &[u8], data: &[u8], persistent: u32) -> Result<Vec<u8>> {
        let (selections, per_pcr) = self.pcr_live(pcrs)?;
        let policy_digest = policy_pcr_auth_policy(&selections, &per_pcr);
        let parent = self.create_storage_parent()?;
        let (name, object_public, private) = self.create_sealed(&parent, data, &policy_digest)?;
        let child = self.load_object(&parent, &object_public, &private)?;
        // The PCRs still match, so a fresh policy session authorizes the
        // object for the EvictControl persistence.
        let session = self.start_policy_pcr_session(&selections, &per_pcr)?;
        self.evict_control_persist_session(child, &name, &session, persistent)?;
        let _ = self.flush_context(session.handle);
        let _ = self.flush_context(child);
        let _ = self.flush_context(parent.handle);
        Ok(name)
    }

    /// Unseal the object at `handle` using the PCR policy `pcrs`.
    pub fn unseal(&mut self, pcrs: &[u8], handle: u32) -> Result<Vec<u8>> {
        let (selections, per_pcr) = self.pcr_live(pcrs)?;
        let (_public, name) = self.read_public_raw(handle)?;
        let session = self.start_policy_pcr_session(&selections, &per_pcr)?;
        let data = self.unseal_obj(handle, &name, &session)?;
        let _ = self.flush_context(session.handle);
        Ok(data)
    }

    /// `TPM2_EvictControl`: make the transient `object` handle persistent at
    /// `persistent`, authorizing the object with `session` (its policy
    /// session). Wire handle order: `objectHandle`, then `authHandle` (owner
    /// hierarchy, empty auth). The single policy session is attached to the
    /// first handle (the object).
    pub fn evict_control_persist_session(
        &mut self,
        object: u32,
        name: &[u8],
        session: &Session,
        persistent: u32,
    ) -> Result<u32> {
        let code = self.wire_cc(cc::EVICT_CONTROL) as u32;
        let auth_handle = if self.dialect {
            rh::OWNER
        } else {
            rh_std::OWNER
        };

        // params = persistentHandle (u32)
        let params: [u8; 4] = persistent.to_be_bytes();

        // cpHash = H(cc || name(object) || name(authHandle) || params).
        // The hierarchy's "name" is the raw 4-byte handle value.
        let mut cp = Vec::new();
        cp.extend_from_slice(&code.to_be_bytes());
        cp.extend_from_slice(name);
        cp.extend_from_slice(&auth_handle.to_be_bytes());
        cp.extend_from_slice(&params);
        // (The TPM computes cpHash from these inputs; a policy session carries
        // no HMAC, so the client does not need the digest.)
        let _ = Sha256::digest(&cp);

        // Policy sessions carry no HMAC (TPM2B of size 0).
        let area_nonce = if self.dialect {
            self.get_random(32)?
        } else {
            session.nonce_caller.clone()
        };
        let mut sess_area = Vec::new();
        sess_area.extend_from_slice(&session.handle.to_be_bytes());
        sess_area.extend_from_slice(&(area_nonce.len() as u16).to_be_bytes());
        sess_area.extend_from_slice(&area_nonce);
        sess_area.push(0); // policy session: no HMAC/encryption attributes
        sess_area.extend_from_slice(&0u16.to_be_bytes()); // hmac size 0

        let mut body = Vec::new();
        body.extend_from_slice(&object.to_be_bytes()); // objectHandle
        body.extend_from_slice(&auth_handle.to_be_bytes()); // authHandle
        if self.dialect {
            body.extend_from_slice(&(sess_area.len() as u32).to_be_bytes());
        }
        body.extend_from_slice(&sess_area);
        body.extend_from_slice(&params);

        let size = (HEADER_SIZE + body.len()) as u32;
        let mut cmd = Vec::with_capacity(size as usize);
        cmd.extend_from_slice(&st::SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&size.to_be_bytes());
        cmd.extend_from_slice(&code.to_be_bytes());
        cmd.extend_from_slice(&body);

        let resp = self.transfer(&cmd)?;
        let (rc, rbody) = crate::conn::parse_response(&resp)?;
        if rc != 0 {
            return Err(Error::Tpm(rc as u16, crate::error::rc_name(rc as u32 as u16)));
        }
        // response: newObjectHandle (u32)
        if rbody.len() < 4 {
            return Err(Error::Malformed("EvictControl: short response".into()));
        }
        Ok(u32::from_be_bytes([rbody[0], rbody[1], rbody[2], rbody[3]]))
    }
}
