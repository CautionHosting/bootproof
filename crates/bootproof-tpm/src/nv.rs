//! TPM2_NV_Read / TPM2_NV_Read_public: reading raw NV index data.
//!
//! An NV index holds opaque bytes. Its metadata (`dataSize`, `attributes`)
//! comes from `TPM2_NV_Read_public` (`TPMT_NV_PUBLIC`); the bytes themselves
//! come from `TPM2_NV_Read`, chunked to the TPM's
//! `TPM_PT_NV_BUFFER_MAX` (property tag 0x012C = TPM_PT_FIXED + 44; NitroTPM
//! advertises 1024, observed live on d13-recon 2026-11-09).
//!
//! The auth method here is a PASSWORD session, not an HMAC session: per
//! TPM 2.0 Part 3 the auth session for an NV read may carry *any* auth-type
//! reserved handle (tss2-tools uses TPM_RS_PW for NV reads), and the
//! password field itself is the empty string for a clear-authorization
//! read (`TPMA_NV_OWNERREAD`/`PPREAD`/`AUTHREAD` indices all take an empty
//! password).
//!
//! Responses are parsed per TPM 2.0 Part 2 with the parameter area only
//! (header and response code stripped):
//!
//! ```text
//! NV_Read_public    -> TPM2B_NV_PUBLIC { u16 size, TPMT_NV_PUBLIC
//!                      { u32 handle, u16 nameAlg, u32 attributes,
//!                      u16 authPolicy.size, policy, u16 dataSize } }
//!                      | TPM2B_NAME  (NO moreData byte: raw capture on
//!                      swtpm 2026-11-09 shows the body starts at the
//!                      TPM2B size directly)
//! NV_Read           -> TPM2B_MAX_NV_BUFFER { u16 size, data }
//! GetCapability     -> moreData u8 | TPMU_CAPABILITIES (selector-prefixed
//!                      TPML_TAGGED_TPM_PROPERTY for CAP_TPM_PROPERTIES)
//! ```

use crate::conn::{Command, Tpm};
use crate::constants::{cc, rh, st};
use crate::error::{Error, Result};

/// TPM_ST_PW_SESSION (the password-session handle). "This was a bug; to be
/// deprecated" per the TSS header comment, but it is what every tool uses.
pub const RS_PW: u32 = 0x4000_0009;

/// TPM_CAP_TPM_PROPERTIES (TPM 2.0 Part 2).
pub const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
/// TPM_PT_NV_BUFFER_MAX (property tag 0x012C = TPM_PT_FIXED + 44): the
/// maximum NV data bytes returned by one NV_Read. NitroTPM advertises 1024
/// (observed live on d13-recon 2026-11-09).
pub const PT_NV_BUFFER_MAX: u32 = 0x0000_012C;

/// The read-authorization bits of TPMA_NV, verified against the installed
/// tss2_tpm2_types.h (TPMA_NV_PPREAD 0x00010000, OWNERREAD 0x00020000,
/// AUTHREAD 0x00040000, POLICYREAD 0x00080000, WRITTEN 0x20000000).
pub const NV_PPREAD: u32 = 0x0001_0000;
pub const NV_OWNERREAD: u32 = 0x0002_0000;
pub const NV_AUTHREAD: u32 = 0x0004_0000;
pub const NV_POLICYREAD: u32 = 0x0008_0000;
/// TPMA_NV_WRITTEN: the index has been written (data is valid).
pub const NV_WRITTEN: u32 = 0x2000_0000;

fn u16_at(b: &[u8], off: usize) -> Result<usize> {
    if b.len() < off + 2 {
        return Err(Error::Malformed("nv: truncated u16".into()));
    }
    Ok(u16::from_be_bytes([b[off], b[off + 1]]) as usize)
}

fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    if b.len() < off + 4 {
        return Err(Error::Malformed("nv: truncated u32".into()));
    }
    Ok(u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]))
}

/// Parsed `TPMT_NV_PUBLIC` (only the fields a reader needs).
#[derive(Debug, Clone, Copy)]
pub struct NvPublicInfo {
    /// `hashAlg`/`nameAlg` (TPM_ALG of the index Name digest).
    pub name_alg: u16,
    /// `attributes` (TPMA_NV).
    pub attributes: u32,
    /// `dataSize`: the declared size of the index.
    pub data_size: u16,
}

/// Parse the parameter area of an `NV_Read_public` response.
/// No moreData byte (see the module doc): `TPM2B_NV_PUBLIC | TPM2B_NAME`.
pub fn parse_nv_public(params: &[u8]) -> Result<NvPublicInfo> {
    if params.len() < 2 {
        return Err(Error::Malformed("nv: empty NV_Read_public".into()));
    }
    let mut off = 0usize;
    let pub_size = u16_at(params, off)?;
    off += 2;
    if params.len() < off + pub_size {
        return Err(Error::Malformed("nv: NV_Read_public truncated".into()));
    }
    // TPMT_NV_PUBLIC inside the TPM2B.
    let end = off + pub_size;
    let mut p = off;
    let _handle = u32_at(params, p)?; // index handle (echoes the request)
    p += 4;
    let name_alg = u16_at(params, p)? as u16;
    p += 2;
    let attributes = u32_at(params, p)?;
    p += 4;
    let policy_size = u16_at(params, p)?;
    p += 2 + policy_size;
    // dataSize is the LAST u16 of TPMT_NV_PUBLIC: it must sit exactly at
    // the end of the TPM2B. Anchoring the parse at the end catches a
    // malformed authPolicy size instead of reading past the structure.
    if end < p + 2 {
        return Err(Error::Malformed("nv: NV_Read_public missing dataSize".into()));
    }
    let data_size = u16_at(params, end - 2)? as u16;
    Ok(NvPublicInfo { name_alg, attributes, data_size })
}

/// Parse the parameter area of an `NV_Read` response. NV_Read is always a
/// SESSIONS command, so the body is `paramSize u32 | TPM2B_MAX_NV_BUFFER
/// { u16 size, data } | <response session area>`. The paramSize is skipped;
/// the trailing session area (nonceTPM/attrs/hmac) is not our concern.
///
/// (Omitting the paramSize skip reads the u32's high two bytes as the TPM2B
/// size and silently returns empty -- the second half of the live-caught
/// bug: paramSize=0x00000022 looks like size 0 unless you step past it.)
pub fn parse_nv_read(params: &[u8]) -> Result<Vec<u8>> {
    if params.len() < 4 {
        return Err(Error::Malformed("nv: NV_Read missing paramSize".into()));
    }
    let size = u16_at(params, 4)?;
    if params.len() < 6 + size {
        return Err(Error::Malformed("nv: NV_Read data truncated".into()));
    }
    Ok(params[6..6 + size].to_vec())
}

/// Find `TPM_PT_NV_BUFFER_MAX` in the parameter area of a GetCapability
/// response for CAP_TPM_PROPERTIES. `Some(v)` only when the property is
/// present; any other outcome (wrong selector, truncation) is `None` and
/// the caller falls back to a conservative cap.
pub fn parse_max_nv_buffer(params: &[u8]) -> Option<u16> {
    // moreData u8 | TPMU_CAPABILITIES = u32 selector | TPML_TAGGED... when
    // the selector matches CAP_TPM_PROPERTIES.
    if params.len() < 5 || u32_at(params, 1).ok()? != CAP_TPM_PROPERTIES {
        return None;
    }
    let mut off = 5usize;
    let count = u32_at(params, off).ok()? as usize;
    off += 4;
    for _ in 0..count {
        // TPMS_TAGGED_PROPERTY { u32 property, u32 value }
        let prop = u32_at(params, off).ok()?;
        let val = u32_at(params, off + 4).ok()?;
        off += 8;
        if prop == PT_NV_BUFFER_MAX {
            return Some(val as u16);
        }
    }
    None
}

/// Read the metadata of an NV index (`TPM2_NV_Read_public`, no auth needed).
/// `Tpm::call` already maps a non-SUCCESS response code to `Error::Tpm`.
pub fn nv_read_public(tpm: &mut Tpm, index: u32) -> Result<NvPublicInfo> {
    let mut cmd = Command::new(cc::NV_READ_PUBLIC, st::NO_SESSIONS);
    cmd.push_u32(index);
    let (_rc, params) = tpm.call(&cmd)?;
    parse_nv_public(&params)
}

/// One authorized NV read of `size` bytes at `offset` (password session,
/// empty password). `auth` is the authorization handle appropriate to the
/// index's read attributes: TPM_RH_OWNER for OWNERREAD, TPM_RH_ENDORSEMENT
/// for AUTHREAD, TPM_RH_PLATFORM for PPREAD; TPM_RS_PW itself is also
/// spec-legal for a clear-authorization read (tss2-tools uses it).
pub fn nv_read(
    tpm: &mut Tpm,
    auth: u32,
    index: u32,
    offset: u16,
    size: u16,
) -> Result<Vec<u8>> {
    let mut cmd = Command::new(cc::NV_READ, st::SESSIONS);
    cmd.push_u32(auth);
    cmd.push_u32(index);
    // authSize u32: a PASSWORD session area is 9 octets:
    // handle(4) | nonceSize(2)=0 | attrs(1) | hmacSize(2)=0. (An HMAC
    // session is the same SHAPE but with 32-octet nonces/digests; the
    // 12-octet layout I first wrote here was wrong -- swtpm answered
    // 0x0A9A "not enough octets" because the parse ran 3 bytes into the
    // parameters. Verified live 2026-11-09: authSize=9 reads OK.)
    cmd.push_u32(9);
    cmd.push_u32(RS_PW);
    cmd.push_u16(0);
    cmd.push_u8(1); // TPMA_SESSION_CONTINUESESSION
    cmd.push_u16(0); // empty password
    // TPM2_NV_Read parameters are size THEN offset (Part 3 command layout).
    // Reversing them is the bug the live witness caught: (offset=0, size=N)
    // marshals as (size=0, offset=N), a LEGAL zero-byte read that returns an
    // empty buffer with rc=SUCCESS rather than erroring. swtpm 2026-11-09.
    cmd.push_u16(size);
    cmd.push_u16(offset);
    let (_rc, params) = tpm.call(&cmd)?;
    parse_nv_read(&params)
}

/// The NV read-authorization handle for a given TPMA_NV attribute set,
/// or None if no clear-authorization read path exists.
pub fn nv_read_auth_handle(attributes: u32) -> Option<u32> {
    if attributes & NV_OWNERREAD != 0 {
        Some(rh::OWNER)
    } else if attributes & NV_AUTHREAD != 0 {
        Some(rh::ENDORSEMENT)
    } else if attributes & NV_PPREAD != 0 {
        Some(rh::PLATFORM)
    } else if attributes & NV_POLICYREAD != 0 {
        // A policy-read index needs the authValue or a satisfied policy;
        // a clear read is impossible.
        None
    } else {
        // No read-auth bits set: only admin (owner/platform) authorization
        // can read; try OWNER, it is the common case for vendor indices.
        Some(rh::OWNER)
    }
}

/// The max NV read chunk: the live `TPM_PT_NV_BUFFER_MAX` when GetCapability
/// answers, else the conservative floor of 512 (every TPM 2.0 supports at
/// least that much for NV buffers per the TSS minimums; NitroTPM: 1024).
pub fn max_nv_buffer(tpm: &mut Tpm) -> u16 {
    let mut cmd = Command::new(cc::GET_CAPABILITY, st::NO_SESSIONS);
    cmd.push_u32(CAP_TPM_PROPERTIES);
    cmd.push_u32(PT_NV_BUFFER_MAX);
    cmd.push_u32(1);
    match tpm.call(&cmd) {
        Ok((_rc, params)) => match parse_max_nv_buffer(&params) {
            Some(v) if v > 0 => v,
            _ => 512,
        },
        _ => 512,
    }
}

/// Read the full data of an NV index, chunked to the TPM's max NV buffer.
/// Returns the `data_size` bytes declared by `nv_read_public`. Fails if any
/// chunk errors or the index reads short.
pub fn nv_read_index(tpm: &mut Tpm, index: u32) -> Result<Vec<u8>> {
    let pubi = nv_read_public(tpm, index)?;
    let auth = nv_read_auth_handle(pubi.attributes)
        .ok_or_else(|| Error::Malformed("nv: index has no clear read path".into()))?;
    let max = max_nv_buffer(tpm);
    let mut out: Vec<u8> = Vec::with_capacity(pubi.data_size as usize);
    let size = pubi.data_size;
    let mut off: u16 = 0;
    while (off as usize) < size as usize {
        let want = std::cmp::min(max, size - off);
        if want == 0 {
            break;
        }
        let chunk = nv_read(tpm, auth, index, off, want)?;
        if chunk.is_empty() {
            // Zero-length read where data was expected: the TPM is refusing
            // to give more (auth/lock). Fail, don't pad.
            return Err(Error::Malformed(format!(
                "nv: read stalled at offset {off} of {size}"
            )));
        }
        out.extend_from_slice(&chunk);
        off += chunk.len() as u16;
    }
    if out.len() != size as usize {
        return Err(Error::Malformed(format!(
            "nv: index 0x{index:08X} read {} of {size} bytes",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nv_public_end_anchored() {
        // TPM2B(34): { handle 0x01C00002, nameAlg 0x000B,
        // attrs 0x20020006 (OWNERREAD|WRITTEN|...), authPolicy size 16,
        // 16 policy bytes, dataSize 1024 }, then a TPM2B_NAME follows
        // (the parser must ignore everything past the TPM2B).
        let mut tpm2b: Vec<u8> = Vec::new();
        tpm2b.extend_from_slice(&0x01C0_0002u32.to_be_bytes());
        tpm2b.extend_from_slice(&0x000Bu16.to_be_bytes());
        tpm2b.extend_from_slice(&0x2002_0006u32.to_be_bytes());
        tpm2b.extend_from_slice(&16u16.to_be_bytes());
        tpm2b.extend_from_slice(&[0xABu8; 16]);
        tpm2b.extend_from_slice(&1024u16.to_be_bytes());
        let mut params: Vec<u8> = Vec::new();
        params.extend_from_slice(&(tpm2b.len() as u16).to_be_bytes());
        params.extend_from_slice(&tpm2b);
        // Trailing TPM2B_NAME (size 34 + 34 bytes): must not affect the parse.
        params.extend_from_slice(&34u16.to_be_bytes());
        params.extend_from_slice(&[0xCDu8; 34]);
        let p = parse_nv_public(&params).expect("parses");
        assert_eq!(p.name_alg, 0x000B);
        assert_eq!(p.attributes, 0x2002_0006);
        assert_eq!(p.data_size, 1024);
        assert_eq!(p.attributes & NV_WRITTEN, NV_WRITTEN);
        assert_eq!(p.attributes & NV_OWNERREAD, NV_OWNERREAD);
    }

    #[test]
    fn rejects_truncated_nv_public() {
        assert!(parse_nv_public(&[]).is_err());
        // TPM2B size promises more than the buffer carries.
        assert!(parse_nv_public(&[0, 100]).is_err());
    }

    #[test]
    fn parses_nv_read() {
        // paramSize u32 (0x22=34) | TPM2B size 0x20 (32)... but here a
        // 2-byte payload: paramSize=4, size=2, DEAD, then a 5-byte session.
        let mut p: Vec<u8> = Vec::new();
        p.extend_from_slice(&4u32.to_be_bytes()); // paramSize = 2 + 2
        p.extend_from_slice(&2u16.to_be_bytes()); // TPM2B size
        p.extend_from_slice(&[0xDE, 0xAD]);
        p.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00]); // session area
        assert_eq!(parse_nv_read(&p).unwrap(), vec![0xDE, 0xAD]);
        // Truncated: fewer than the promised TPM2B bytes.
        assert!(parse_nv_read(&[0, 0, 0, 4, 0, 4, 1, 2]).is_err());
        // Missing even the paramSize.
        assert!(parse_nv_read(&[]).is_err());
        assert!(parse_nv_read(&[0, 0, 0]).is_err());
    }

    #[test]
    fn finds_max_nv_buffer_property() {
        // moreData=0 | selector | count=2 | (PT_MANUFACTURER, junk) |
        // (PT_NV_BUFFER_MAX, 1024)
        let mut params: Vec<u8> = vec![0];
        params.extend_from_slice(&CAP_TPM_PROPERTIES.to_be_bytes());
        params.extend_from_slice(&2u32.to_be_bytes());
        params.extend_from_slice(&0x0000_0105u32.to_be_bytes());
        params.extend_from_slice(&0xDEADu32.to_be_bytes());
        params.extend_from_slice(&PT_NV_BUFFER_MAX.to_be_bytes());
        params.extend_from_slice(&1024u32.to_be_bytes());
        assert_eq!(parse_max_nv_buffer(&params), Some(1024));
        // Wrong selector: not found.
        let mut bad = params.clone();
        bad[1..5].copy_from_slice(&0x0000_0005u32.to_be_bytes());
        assert_eq!(parse_max_nv_buffer(&bad), None);
        // Truncated: not found (caller floors to 512).
        assert_eq!(parse_max_nv_buffer(&params[..4]), None);
    }

    #[test]
    fn read_auth_handle_selection() {
        assert_eq!(nv_read_auth_handle(NV_OWNERREAD), Some(rh::OWNER));
        assert_eq!(nv_read_auth_handle(NV_AUTHREAD), Some(rh::ENDORSEMENT));
        assert_eq!(nv_read_auth_handle(NV_PPREAD), Some(rh::PLATFORM));
        assert_eq!(nv_read_auth_handle(NV_POLICYREAD), None);
        assert_eq!(nv_read_auth_handle(0), Some(rh::OWNER));
    }
}
