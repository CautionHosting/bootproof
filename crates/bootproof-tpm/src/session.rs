//! HMAC auth sessions (unbound, empty-auth) for TPM2 commands.
//!
//! Protocol verified against the reference implementations:
//! - ms-tpm-20-ref / libtpms (TPM side): `ComputeCommandHMAC`, `ComputeCpHash`,
//!   `SessionCreate`, `EntityGetName`.
//! - tpm2-tss ESAPI/SAPI (client side): `Tss2_Sys_StartAuthSession_Prepare/
//!   Complete`, `iesys_compute_cp_hash`, `iesys_crypto_authHmac`.
//!
//! StartAuthSession request (standard TCG layout, verified against
//! tpm2-tss `Tss2_Sys_StartAuthSession_Prepare`):
//! ```text
//! tpmKey          u32        (TPMI_DH_OBJECT; TPM_RH_NULL = unsalted)
//! bind            u32        (TPM_RH_NULL = unbound)
//! nonceCaller     TPM2B { u16 size, bytes }   (32 bytes for SHA256)
//! encryptedSalt   TPM2B { u16 size = 0 }      (empty: unsalted)
//! sessionType     u8         (standard: 0x01 HMAC, 0x02 policy, 0x03 trial)
//! symmetricAlg    u16        = 0x0010 (TPM_ALG_NULL)
//! authHash        u16        = 0x000B (SHA256)
//! ```
//! The platform dialect omits `encryptedSalt` and adds a `keyBits u16 = 0`
//! field instead.
//!
//! This TPM's responses use a 10-byte header (tag, size, responseCode), so
//! the responseCode is read at offset 6 and the body starts at offset 10.
//! StartAuthSession response body:
//! ```text
//! sessionHandle u32        (TPM-assigned; 0x02xxxxxx for HMAC sessions,
//!                           0x03xxxxxx for policy sessions)
//! nonceTPM      TPM2B { u16 size, bytes }
//! ```
//!
//! Session key: an unbound session has no session key. The request HMAC key
//! is `sessionKey || authValue`; for a hierarchy with an empty auth value the
//! key is empty. The TPM accepts either an empty HMAC or the real HMAC with an
//! empty key; we send the real one (matching the ESAPI).
//!
//! cpHash = H( commandCode u32 || authNames... || parameters )
//! - no command tag, no size field
//! - the "name" of a reserved hierarchy handle is its raw 4-byte value
//!   (`EntityGetName`: "For all other types, the handle is the Name")
//!
//! request HMAC = HMAC_SHA256( key, cpHash || nonceCaller || nonceTPM || sessionAttributes )
//! - all inputs are raw buffers (no TPM2B size prefixes)
//!
//! Command with one HMAC session (this platform places the session area
//! AFTER the handles and BEFORE the parameters):
//! ```text
//! tag           u16 = 0x8002 (TPM_ST_SESSIONS)
//! size          u32
//! code          u32
//! authHandle    u32
//! [dialect only] u32 = byte length of the session area that follows
//! --- session area (73 bytes for a 32-byte nonce) ---
//! sessionHandle u32 (from the StartAuthSession response)
//! nonceCaller   TPM2B { u16 size, bytes }
//! attributes    u8   standard: 0x00 (no bits; 0x01 is the audit bit)
//!                           dialect:  0x01
//! hmac          TPM2B { u16 size, bytes }
//! parameters    ...
//! ```
//! The dialect prefixes the session area with a u32 length and sets the
//! attributes byte to 0x01; the standard layout has neither.

use digest::Digest;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constants::{alg, cc, st};
use crate::conn::{Command, Tpm, HEADER_SIZE};
use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

pub const TPM_SE_HMAC: u8 = 0x00;
pub const TPM_SE_POLICY: u8 = 0x01;
pub const TPM_SE_TRIAL: u8 = 0x02;
/// sessionAttributes for the per-command session area. Standard: 0x00 (no
/// bits), matching tss2-esys for a plain session. Dialect: 0x01, matching
/// the platform's working tss2 stack (its low-order bit numbering is
/// shifted, as with the other TPMA fields). The same byte goes into the
/// request HMAC.
pub(crate) fn session_attrs(dialect: bool) -> u8 {
    if dialect {
        0x01
    } else {
        SESSION_ATTRS
    }
}

const SESSION_ATTRS: u8 = 0x00;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| Error::Other(format!("hmac key: {e}")))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// An unbound empty-auth session.
pub struct Session {
    /// TPM-assigned session handle (from the StartAuthSession response).
    pub handle: u32,
    /// The session type (TPM_SE): 0x00 = HMAC, 0x01 = policy, 0x02 = trial.
    pub session_type: u8,
    /// The nonce this caller generated and sends in every session area.
    pub nonce_caller: Vec<u8>,
    /// The nonce the TPM generated (response of StartAuthSession).
    pub nonce_tpm: Vec<u8>,
}

impl Tpm {
    /// Start an unbound HMAC session.
    ///
    /// `auth_handle` is StartAuthSession's `authHandle` (TPMI_ST_AUTH_START).
    /// The ESAPI sends `TPM_RH_NULL` for an unbound session, but a reserved
    /// handle is also legal; some TPM implementations are picky, so it is a
    /// parameter. `session_type` is `TPM_SE` (0x00 = HMAC, 0x01 = policy).
    /// Request/response bytes are logged unconditionally for debugging.
    pub fn start_auth_session(&mut self, auth_handle: u32, session_type: u8) -> Result<Session> {
        // Nonce size must equal the authHash digest size (SHA256 -> 32 bytes).
        // A 16-byte nonce with a SHA256 session makes the TPM reject the
        // follow-on command with TPM_RC_SIZE (0x0095).
        let nonce_caller = self.get_random(32)?;
        self.start_auth_session_nonce(auth_handle, session_type, Some(&nonce_caller))
    }

    /// Like `start_auth_session` but with a caller-supplied nonce (32 bytes
    /// for SHA256), or `None` to draw one via TPM2_GetRandom.
    pub fn start_auth_session_nonce(
        &mut self,
        auth_handle: u32,
        session_type: u8,
        nonce_caller: Option<&[u8]>,
    ) -> Result<Session> {
        let nonce_caller = match nonce_caller {
            Some(n) => n.to_vec(),
            None => self.get_random(32)?,
        };
        // The internal `TPM_SE_*` values are the platform dialect's
        // numbering (HMAC=0x00, policy=0x01, trial=0x02). The standard
        // spec inserts TPM_SE_PASSWORD=0x00, shifting HMAC=0x01,
        // policy=0x02, trial=0x03.
        let wire_type = if self.dialect { session_type } else { session_type + 1 };
        let mut cmd = Command::new(cc::START_AUTH_SESSION, st::NO_SESSIONS);
        cmd.push_u32(auth_handle); // tpmKey (salt key; TPM_RH_NULL = unsalted)
        cmd.push_u32(0x4000_0007); // bind = TPM_RH_NULL (unbound)
        cmd.push_u16(nonce_caller.len() as u16);
        cmd.push_bytes(&nonce_caller); // nonceCaller
        if self.dialect {
            // Dialect tail: keyBits (0) | sessionType | symmetric alg | authHash.
            cmd.push_u16(0); // keyBits
            cmd.push_u8(wire_type); // sessionType
            cmd.push_u16(alg::NULL); // symmetric.algorithm = TPM_ALG_NULL
            cmd.push_u16(alg::SHA256); // authHash
        } else {
            // Standard TCG order (verified against tpm2-tss
            // Tss2_Sys_StartAuthSession_Prepare): tpmKey | bind | nonceCaller
            // | encryptedSalt | sessionType | symmetric | authHash.
            // Unsalted session: encryptedSalt is an empty TPM2B.
            cmd.push_u16(0); // encryptedSalt (size 0)
            cmd.push_u8(wire_type); // sessionType
            cmd.push_u16(alg::NULL); // symmetric.algorithm = TPM_ALG_NULL
            cmd.push_u16(alg::SHA256); // authHash
        }

        let cmd = cmd.encode();
        eprintln!("[session] SAS cmd ({}B): {}", cmd.len(), hex(&cmd));
        let resp = self.transfer(&cmd)?;
        eprintln!("[session] SAS resp ({}B): {}", resp.len(), hex(&resp));
        if resp.len() < HEADER_SIZE {
            return Err(Error::Malformed("StartAuthSession: short response".into()));
        }
        // This TPM's response header is 10 bytes: responseCode at offset 6.
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        let body = &resp[HEADER_SIZE..];
        if rc != 0 {
            return Err(Error::Other(format!(
                "StartAuthSession RC=0x{:08x}",
                rc
            )));
        }
        // [sessionHandle u32][nonceTPM TPM2B]
        if body.len() < 4 + 2 {
            return Err(Error::Malformed("StartAuthSession: short response".into()));
        }
        let session_handle = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let nt_len = u16::from_be_bytes([body[4], body[5]]) as usize;
        if body.len() < 6 + nt_len {
            return Err(Error::Malformed("StartAuthSession: truncated nonceTPM".into()));
        }
        let nonce_tpm = body[6..6 + nt_len].to_vec();
        eprintln!(
            "[session] handle=0x{:08x} nonce_tpm={}B",
            session_handle,
            nonce_tpm.len()
        );
        Ok(Session {
            handle: session_handle,
            session_type,
            nonce_caller,
            nonce_tpm,
        })
    }

    /// Send a CreatePrimary with one attached HMAC session and return the raw
    /// response code (even on failure). `auth_handle` is the command's
    /// authorization handle (e.g. a hierarchy): it goes into the command and
    /// into the cpHash as the entity name. `params` are the marshaled command
    /// parameters (inSensitive, inPublic, outsideInfo, creationPCR).
    pub fn call_create_primary_with_session(
        &mut self,
        auth_handle: u32,
        session: &Session,
        in_sensitive: &[u8],
        in_public: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        // cpHash uses the wire code (identical to the spec code today).
        let code = self.wire_cc(cc::CREATE_PRIMARY) as u32;
        let attrs = session_attrs(self.dialect);
        let mut params = Vec::new();
        // inSensitive is a TPMS_SENSITIVE_CREATE (userAuth TPM2B, data
        // TPM2B) - a fixed-size structure with no size prefix in the
        // standard spec. The StageX firmware dialect additionally wraps it
        // in a u16 size prefix (verified against working esys traffic).
        if self.dialect {
            params.extend_from_slice(&(in_sensitive.len() as u16).to_be_bytes());
        }
        params.extend_from_slice(in_sensitive);
        params.extend_from_slice(&(in_public.len() as u16).to_be_bytes());
        params.extend_from_slice(in_public);
        params.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo (empty)
        // creationPCR: TPML_PCR_SELECTION with count = 0 (key not bound to any
        // PCR) marshals to 4 zero bytes. Verified against tss2 4.1.3.
        params.extend_from_slice(&0x0000_0000u32.to_be_bytes());

        // cpHash = H(code || authName || params); hierarchy name = raw handle.
        let mut cp = Vec::new();
        cp.extend_from_slice(&code.to_be_bytes());
        cp.extend_from_slice(&auth_handle.to_be_bytes());
        cp.extend_from_slice(&params);
        let cp_hash = Sha256::digest(&cp);

        // Unbound + empty auth: HMAC key is empty. (HMAC sessions only; an
        // explicit/policy session carries no auth HMAC at all.)
        let req_hmac = if session.session_type == TPM_SE_HMAC {
            // Message = cpHash || nonceCaller || nonceTPM || attrs (raw buffers).
            let mut msg = Vec::new();
            msg.extend_from_slice(&cp_hash);
            msg.extend_from_slice(&session.nonce_caller);
            msg.extend_from_slice(&session.nonce_tpm);
            msg.push(attrs); // sessionAttributes
            let h = hmac_sha256(&[], &msg)?;
            eprintln!("[session] cpHash={}", hex(&cp_hash));
            eprintln!("[session] reqHmac={}", hex(&h));
            Some(h)
        } else {
            eprintln!("[session] explicit session, no HMAC");
            None
        };

        // Session area: sessionHandle | nonceCaller TPM2B | attributes |
        // hmac TPM2B, placed between the handles and the parameters. The
        // dialect prefixes the area with its u32 size.
        let mut sess_area = Vec::new();
        sess_area.extend_from_slice(&session.handle.to_be_bytes());
        sess_area.extend_from_slice(&(session.nonce_caller.len() as u16).to_be_bytes());
        sess_area.extend_from_slice(&session.nonce_caller);
        sess_area.push(attrs); // sessionAttributes
        match &req_hmac {
            Some(h) => {
                sess_area.extend_from_slice(&(h.len() as u16).to_be_bytes());
                sess_area.extend_from_slice(h);
            }
            // Empty auth value: a size-0 TPM2B.
            None => sess_area.extend_from_slice(&0u16.to_be_bytes()),
        }

        let mut body = Vec::new();
        // handles section: primaryHandle (the hierarchy being authorized).
        body.extend_from_slice(&auth_handle.to_be_bytes());
        // The dialect prefixes the session area with a u32 size; the
        // standard layout has no such prefix (sessions are self-delimiting).
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
        eprintln!("[session] cmd ({}B): {}", cmd.len(), hex(&cmd));

        let resp = self.transfer(&cmd)?;
        eprintln!("[session] resp ({}B): {}", resp.len(), hex(&resp));
        if resp.len() < HEADER_SIZE {
            return Err(Error::Malformed("short session response".into()));
        }
        // responseCode at offset 6 (this TPM's 10-byte response header).
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        Ok((rc, resp[HEADER_SIZE..].to_vec()))
    }

    /// Send any command with one attached unbound HMAC session.
    /// `entity_name` is the authorization entity's Name for the cpHash (raw
    /// 4-byte handle for hierarchies, the key's `Name` for transient keys,
    /// an NV index's Name for NV commands). `handles` is the command's
    /// handles section; `params` its parameters; `auth_value` the entity's
    /// auth value (empty for a hierarchy with no password). Returns
    /// (responseCode, body).
    pub fn call_with_session(
        &mut self,
        cc_code: u32,
        entity_name: &[u8],
        handles: &[u32],
        params: &[u8],
        session: &Session,
        auth_value: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        // cpHash = H(code || entityName || params).
        let mut cp = Vec::new();
        cp.extend_from_slice(&cc_code.to_be_bytes());
        cp.extend_from_slice(entity_name);
        cp.extend_from_slice(params);
        let cp_hash = Sha256::digest(&cp);

        // Dialect: the command's session area must carry a FRESH caller
        // nonce. The dialect tracks used nonces (replay protection,
        // observed RC 0x04d6); reusing the SAS request's nonce in the
        // command area is rejected with 0x014c. The platform's own
        // tpm2-tools generates a new nonce per command (captured: SAS
        // nonce and command-area nonce always differ).
        let area_nonce = if self.dialect {
            self.get_random(32)?
        } else {
            session.nonce_caller.clone()
        };
        let req_hmac = if session.session_type == TPM_SE_HMAC {
            // Unbound session: sessionKey is empty, so the HMAC key is just
            // the auth value (empty for an empty-auth hierarchy).
            let mut msg = Vec::new();
            msg.extend_from_slice(&cp_hash);
            msg.extend_from_slice(&area_nonce);
            msg.extend_from_slice(&session.nonce_tpm);
            msg.push(session_attrs(self.dialect));
            Some(hmac_sha256(auth_value, &msg)?)
        } else {
            None
        };
        // Policy sessions carry no parameter encryption and no HMAC; the
        // decrypt/encrypt bits must be clear (libtpms rejects the decrypt bit
        // on commands without encryptable params: TPM_RCS_ATTRIBUTES).
        let area_attrs = if session.session_type == TPM_SE_HMAC {
            session_attrs(self.dialect)
        } else {
            0
        };

        // Session area: sessionHandle | nonceCaller TPM2B | attributes |
        // hmac TPM2B, placed after the handles and before the parameters.
        // The dialect prefixes the area with a u32 size.
        let mut sess_area = Vec::new();
        sess_area.extend_from_slice(&session.handle.to_be_bytes());
        sess_area.extend_from_slice(&(area_nonce.len() as u16).to_be_bytes());
        sess_area.extend_from_slice(&area_nonce);
        sess_area.push(area_attrs);
        match &req_hmac {
            Some(h) => {
                sess_area.extend_from_slice(&(h.len() as u16).to_be_bytes());
                sess_area.extend_from_slice(h);
            }
            // Policy sessions carry an empty HMAC (TPM2B of size 0).
            None => sess_area.extend_from_slice(&0u16.to_be_bytes()),
        }

        let mut body = Vec::new();
        for h in handles {
            body.extend_from_slice(&h.to_be_bytes());
        }
        // The dialect prefixes the session area with a u32 size; the
        // standard layout has no such prefix (sessions are self-delimiting).
        if self.dialect {
            body.extend_from_slice(&(sess_area.len() as u32).to_be_bytes());
        }
        body.extend_from_slice(&sess_area);
        body.extend_from_slice(params);

        let size = (HEADER_SIZE + body.len()) as u32;
        let mut cmd = Vec::with_capacity(size as usize);
        cmd.extend_from_slice(&st::SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&size.to_be_bytes());
        cmd.extend_from_slice(&cc_code.to_be_bytes());
        cmd.extend_from_slice(&body);
        eprintln!("[session] cmd ({}B): {}", cmd.len(), hex(&cmd));

        let resp = self.transfer(&cmd)?;
        eprintln!("[session] resp ({}B): {}", resp.len(), hex(&resp));
        if resp.len() < HEADER_SIZE {
            return Err(Error::Malformed("short session response".into()));
        }
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        Ok((rc, resp[HEADER_SIZE..].to_vec()))
    }
}
