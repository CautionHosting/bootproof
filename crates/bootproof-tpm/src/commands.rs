//! No-session TPM2 commands: Startup, GetTestResult, PCR_Read, GetRandom,
//! GetCapability. These need no auth session (tag 0x8001), which makes them
//! the de-risking target for the raw protocol.
//!
//! Each command is split into a pure `build_*` (marshals the request body) and
//! a pure `parse_*` (unmarshals the response body) so the protocol logic can be
//! unit-tested against captured byte fixtures without a live TPM.
//!
//! Wire format (verified against the Linux kernel, TSS2, and captured
//! tpm2-tools traffic on a reference swtpm):
//! * Header: `{tag u16, size u32, code u32}` big-endian (see [`crate::conn`]).
//! * `TPML_*` arrays carry a `u32` count.
//! * `TPMS_PCR_SELECTION` is `{hash u16, pcrSelectSize u8, pcrSelect[size]}`.

use crate::constants::{alg, cap, cc, ht, st};
use crate::conn::{Command, Tpm};
use crate::error::{Error, Result};

/// A PCR selection: one hash algorithm + a 3-byte bitmap covering PCR 0-23.
///
/// byte 0 = PCR 0-7, byte 1 = PCR 8-15, byte 2 = PCR 16-23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcrSelection {
    pub hash: u16,
    pub pcr_select: [u8; 3],
}

impl PcrSelection {
    /// Select the given PCR indices for a hash algorithm.
    pub fn new(hash: u16, indices: &[u8]) -> Self {
        let mut sel = [0u8; 3];
        for &i in indices {
            if (i as usize) < 24 {
                sel[(i as usize) / 8] |= 1 << (i as usize) % 8;
            }
        }
        Self {
            hash,
            pcr_select: sel,
        }
    }

    /// All 24 PCRs (0-23).
    pub fn all(hash: u16) -> Self {
        Self {
            hash,
            pcr_select: [0xFF, 0xFF, 0xFF],
        }
    }

    /// Rebuild from a raw `TPMS_PCR_SELECTION` (hash u16 | size u8 | bytes),
    /// e.g. one echoed in a Quote's `TPML_PCR_SELECTION`.
    pub fn from_raw(raw: &[u8]) -> Option<Self> {
        if raw.len() < 3 {
            return None;
        }
        let hash = u16::from_be_bytes([raw[0], raw[1]]);
        let size = raw[2] as usize;
        if raw.len() < 3 + size {
            return None;
        }
        let mut sel = [0u8; 3];
        sel[..size.min(3)].copy_from_slice(&raw[3..3 + size.min(3)]);
        Some(Self { hash, pcr_select: sel })
    }

    /// Serialize as a `TPMS_PCR_SELECTION`: `{hash u16, size u8, pcrSelect[3]}`
    /// = 6 bytes.
    pub fn encode(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0..2].copy_from_slice(&self.hash.to_be_bytes());
        out[2] = 3; // pcrSelectSize
        out[3..6].copy_from_slice(&self.pcr_select);
        out
    }

    /// The selected PCR indices, ascending.
    pub fn indices(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for (b, byte) in self.pcr_select.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1u8 << bit) != 0 {
                    v.push(b as u8 * 8 + bit as u8);
                }
            }
        }
        v
    }
}

/// One PCR value from a PCR_Read response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrValue {
    pub digest: Vec<u8>,
}

/// Result of TPM2_PCR_Read.
#[derive(Debug, Clone)]
pub struct PcrReadResult {
    /// Leading `u32` of the response (the kernel calls it `update_cnt`; the TPM
    /// echoes a counter here). Kept for completeness.
    pub update_counter: u32,
    /// Values in request order (flattened). For one selection of all PCRs,
    /// this is PCR 0..N in order.
    pub values: Vec<PcrValue>,
    /// The TPM's echo of which PCRs were actually returned (`pcrSelectionOut`,
    /// first entry). Reflects the intersection of the request and the TPM's
    /// allocated PCRs, so callers can adapt to the real PCR set.
    pub selection: Option<PcrSelection>,
}

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

/// Marshal a TPM2_PCR_Read request (no sessions).
///
/// Body: `pcrSelectionIn TPML_PCR_SELECTION { count u32, selection[] }`.
pub fn build_pcr_read_cmd(selections: &[PcrSelection]) -> Command {
    let mut cmd = Command::new(cc::PCR_READ, st::NO_SESSIONS);
    cmd.push_u32(selections.len() as u32);
    for s in selections {
        cmd.push_bytes(&s.encode());
    }
    cmd
}

/// Parse a TPM2_PCR_Read response body (after the header).
///
/// Body layout (matches the kernel `struct tpm2_pcr_read_out`):
/// ```text
/// update_cnt        u32
/// pcrSelectionOut   TPML_PCR_SELECTION { count u32, selection[] }
/// pcrValues         TPML_PCR_VALUE     { count u32, TPM2B_DIGEST[] }
/// ```
pub fn parse_pcr_read(body: &[u8]) -> Result<PcrReadResult> {
    let update_counter = read_u32(body, 0)?;
    let mut off = 4usize;

    // pcrSelectionOut: { count u32, selection[count] }.
    let sel_out_count = read_u32(body, off)? as usize;
    off += 4;
    let mut selection = None;
    for idx in 0..sel_out_count {
        let hash = read_u16(body, off)?;
        off += 2;
        // pcrSelectSize u8 + pcrSelect[size]
        let sel_size = *body
            .get(off)
            .ok_or_else(|| Error::Malformed("truncated pcrSelect".into()))?
            as usize;
        let pcr_start = off + 1;
        let n = sel_size.min(3);
        if body.len() < pcr_start + n {
            return Err(Error::Malformed("truncated pcrSelect bytes".into()));
        }
        if idx == 0 {
            let mut pcr_select = [0u8; 3];
            pcr_select[..n].copy_from_slice(&body[pcr_start..pcr_start + n]);
            selection = Some(PcrSelection { hash, pcr_select });
        }
        off += 1 + sel_size;
    }

    // pcrValues: { count u32, TPM2B_DIGEST[count] }.
    let value_count = read_u32(body, off)? as usize;
    off += 4;
    let mut values = Vec::with_capacity(value_count);
    for _ in 0..value_count {
        let dlen = read_u16(body, off)? as usize;
        off += 2;
        if body.len() < off + dlen {
            return Err(Error::Malformed("truncated digest".into()));
        }
        let digest = body[off..off + dlen].to_vec();
        off += dlen;
        values.push(PcrValue { digest });
    }

    Ok(PcrReadResult {
        update_counter,
        values,
        selection,
    })
}

impl Tpm {
    /// TPM2_Startup. `state` selects TPM_SU_STATE (1) vs TPM_SU_CLEAR (0).
    pub fn startup(&mut self, state: bool) -> Result<()> {
        let mut cmd = Command::new(cc::STARTUP, st::NO_SESSIONS);
        cmd.push_u16(if state { 0x0001 } else { 0x0000 });
        let (_rc, _body) = self.call(&cmd)?;
        Ok(())
    }

    /// TPM2_GetTestResult. Returns the test result code + the test data.
    ///
    /// Response: `{ testResult u16, testData TPM2B_DIGEST { size u16, octets } }`.
    pub fn get_test_result(&mut self) -> Result<(u16, Vec<u8>)> {
        let cmd = Command::new(cc::GET_TEST_RESULT, st::NO_SESSIONS);
        let (_rc, body) = self.call(&cmd)?;
        if body.len() < 4 {
            return Err(Error::Malformed("GetTestResult body too short".into()));
        }
        let code = read_u16(&body, 0)?;
        let data_len = read_u16(&body, 2)? as usize;
        if body.len() < 4 + data_len {
            return Err(Error::Malformed("truncated GetTestResult".into()));
        }
        let data = body[4..4 + data_len].to_vec();
        Ok((code, data))
    }

    /// TPM2_PCR_Read. Reads the selected PCRs.
    pub fn pcr_read(&mut self, selections: &[PcrSelection]) -> Result<PcrReadResult> {
        let cmd = build_pcr_read_cmd(selections);
        let (_rc, body) = self.call(&cmd)?;
        parse_pcr_read(&body)
    }

    /// TPM2_GetRandom. Returns `n` random bytes (max 32 per call).
    pub fn get_random(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < n {
            let chunk = std::cmp::min(32, n - out.len());
            let mut cmd = Command::new(cc::GET_RANDOM, st::NO_SESSIONS);
            cmd.push_u16(chunk as u16);
            let (_rc, body) = self.call(&cmd)?;
            // response: TPM2B_DIGEST { u16 size, bytes }
            let size = read_u16(&body, 0)? as usize;
            if body.len() < 2 + size {
                return Err(Error::Malformed("truncated GetRandom".into()));
            }
            out.extend_from_slice(&body[2..2 + size]);
        }
        Ok(out)
    }

    /// Map a spec command code to the firmware's wire code. The dialect
    /// renumbers some commands (verified against working esys traffic):
    /// CreatePrimary 0x0135 -> 0x0131, ReadPublic 0x016A -> 0x0173. All
    /// other codes used by this client are unchanged.
    pub fn wire_cc(&self, standard: u16) -> u16 {
        if !self.dialect {
            return standard;
        }
        match standard {
            cc::CREATE_PRIMARY => 0x0131,
            cc::READ_PUBLIC => 0x0173,
            other => other,
        }
    }

    /// TPM2_GetCapability for a single TPM property (TPM_CAP_TPM_PROPERTIES).
    /// Returns the property value (u32).
    pub fn get_property(&mut self, tpm_pt: u32) -> Result<u32> {
        let mut cmd = Command::new(cc::GET_CAPABILITY, st::NO_SESSIONS);
        cmd.push_u32(cap::TPM_PROPERTIES);
        cmd.push_u32(tpm_pt); // property
        cmd.push_u32(1); // propertyLimit
        let (_rc, body) = self.call(&cmd)?;
        parse_get_capability_property(&body)
    }

    /// Detect the renumbered StageX dialect and record it. The dialect
    /// renumbers symmetric algorithms: it advertises CFB as `0x0043`, a code
    /// the spec does not define (spec CFB is `0x0045`). Querying
    /// GetCapability(ALGORITHMS) for `0x0043` therefore marks the dialect:
    /// a count > 0 means the firmware speaks it, NO_RESULT (0x0001) means a
    /// standard TPM. Best effort: on any error the TPM is treated as standard.
    pub fn detect_dialect(&mut self) {
        let mut cmd = Command::new(cc::GET_CAPABILITY, st::NO_SESSIONS);
        cmd.push_u32(cap::ALGS);
        cmd.push_u32(alg::CFB as u32); // sub-cap: CFB id (dialect 0x0043)
        cmd.push_u32(1); // limit: one algorithm entry
        self.dialect = match self.call(&cmd) {
            Ok((_rc, body)) => {
                // body: moreData u8 | capability u32 | count u32 | payload
                if body.len() >= 9 {
                    u32::from_be_bytes([body[5], body[6], body[7], body[8]]) > 0
                } else {
                    false
                }
            }
            Err(_) => false, // can't enumerate -> assume standard
        };
        eprintln!("[dialect] StageX={}", self.dialect);
    }

    /// TPM2_GetCapability(TPMI_CAP_HANDLES, htype) for one handle type.
    ///
    /// Response body: `{ more_data u8, subcap_id u32, count u32, handles[] }`.
    pub fn get_handles(&mut self, htype: u32) -> Result<Vec<u32>> {
        let mut cmd = Command::new(cc::GET_CAPABILITY, st::NO_SESSIONS);
        cmd.push_u32(cap::HANDLES);
        cmd.push_u32(htype);
        cmd.push_u32(0xFFFF_FFFF); // ask for as many as available
        let (_rc, body) = self.call(&cmd)?;
        let count = read_u32(&body, 5)? as usize;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            out.push(read_u32(&body, 9 + i * 4)?);
        }
        Ok(out)
    }

    /// TPM2_FlushContext for a single handle.
    pub fn flush_context(&mut self, handle: u32) -> Result<()> {
        let mut cmd = Command::new(cc::FLUSH_CONTEXT, st::NO_SESSIONS);
        cmd.push_u32(handle);
        let (_rc, _body) = self.call(&cmd)?;
        Ok(())
    }

    /// Enumerate and flush all loaded transient, persistent, and session
    /// handles. Returns the number successfully flushed. Used to recover a TPM
    /// whose context pool has filled up ("out of memory for object contexts").
    ///
    /// Some TPMs do not support enumerating every handle type (they return an
    /// RC for the subcap), so per-type enumeration errors are tolerated.
    pub fn flush_all(&mut self) -> Result<usize> {
        let mut flushed = 0usize;
        // The session handle type differs: 0x02xxxxxx (standard) vs the
        // dialect's 0xA0xxxxxx.
        let session_ht = if self.dialect {
            ht::SESSION
        } else {
            ht::SESSION_STD
        };
        for htype in [
            ht::TRANSIENT,
            ht::PERSISTENT,
            ht::LOADED_METADATA,
            session_ht,
        ] {
            let handles = match self.get_handles(htype) {
                Ok(h) => h,
                Err(_) => continue,
            };
            for h in handles {
                if self.flush_context(h).is_ok() {
                    flushed += 1;
                }
            }
        }
        Ok(flushed)
    }

    /// Flush every handle in the inclusive range `[start..=end]`, ignoring
    /// per-handle errors (non-existent handles are expected). Used to recover
    /// a TPM whose auto-allocated session pool is full ("out of memory for
    /// session contexts") and whose handles are not enumerable via
    /// GetCapability. Returns the number of handles actually flushed.
    pub fn flush_range(&mut self, start: u32, end: u32) -> Result<usize> {
        let mut flushed = 0usize;
        for h in start..=end {
            if self.flush_context(h).is_ok() {
                flushed += 1;
            }
        }
        Ok(flushed)
    }

    /// Flush every auto-allocated session slot (the 0x00/0x01/0x02/0x03
    /// ranges), matching the platform tss2 C stack, which brute-forces these
    /// ranges before its first StartAuthSession. Returns the total number of
    /// handles actually flushed.
    pub fn flush_session_pools(&mut self) -> Result<usize> {
        let mut flushed = 0usize;
        for (start, end) in [
            (0x0000_0000u32, 0x0000_00FFu32),
            (0x0100_0000u32, 0x0100_00FFu32),
            (0x0200_0000u32, 0x0200_00FFu32),
            (0x0300_0000u32, 0x0300_00FFu32),
        ] {
            flushed += self.flush_range(start, end)?;
        }
        Ok(flushed)
    }

    /// TPM2_GetRandom-based nonce (32 bytes) -- a convenience for challenges.
    pub fn nonce32(&mut self) -> Result<[u8; 32]> {
        let b = self.get_random(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        Ok(out)
    }
}

/// Parse a GetCapability(TPM_CAP_TPM_PROPERTIES) response body and return the
/// first property's value.
///
/// Body layout (matches the kernel `struct tpm2_get_cap_out`):
/// ```text
/// more_data   u8
/// subcap_id   u32   (the capability, echoed)
/// count       u32
/// entry[]     { property_id u32, value u32 }
/// ```
pub fn parse_get_capability_property(body: &[u8]) -> Result<u32> {
    let count = read_u32(body, 5)? as usize;
    if count == 0 {
        return Err(Error::Malformed("no properties returned".into()));
    }
    // First entry: property_id u32 (offset 9), value u32 (offset 13).
    let value = read_u32(body, 13)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_selection_encode_sha256_pcr0_1() {
        let s = PcrSelection::new(0x000B, &[0, 1]);
        // hash=0x000B, size=3, pcrSelect byte0 = bits 0,1 = 0x03
        assert_eq!(s.encode(), [0x00, 0x0B, 0x03, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn pcr_selection_all() {
        let s = PcrSelection::all(0x000B);
        assert_eq!(s.encode(), [0x00, 0x0B, 0x03, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn build_pcr_read_cmd_bytes() {
        // 1 selection: sha256, PCRs {0,1}.
        let cmd = build_pcr_read_cmd(&[PcrSelection::new(0x000B, &[0, 1])]);
        // 10-byte header: tag(8001) size(00000014=20) code(0000017E)
        // body: count u32 (00000001) | sel {000B, 03, 030000}
        let expected: Vec<u8> = vec![
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x14, // size = 10 + 10
            0x00, 0x00, 0x01, 0x7E, // PCR_Read
            0x00, 0x00, 0x00, 0x01, // count u32 = 1
            0x00, 0x0B, // hash = sha256
            0x03, // pcrSelectSize
            0x03, 0x00, 0x00, // pcrSelect (PCR 0,1)
        ];
        assert_eq!(cmd.encode(), expected);
    }

    #[test]
    fn pcr_read_header_width() {
        let cmd = build_pcr_read_cmd(&[PcrSelection::all(0x000B)]);
        let enc = cmd.encode();
        // body = count u32 (4) + sel (6) = 10; total = 10 + 10 = 20
        assert_eq!(enc.len(), 20);
        assert_eq!(&enc[2..6], &[0x00, 0x00, 0x00, 0x14]); // size = 20
    }

    #[test]
    fn parse_pcr_read_response() {
        // Real captured fixture (PCR 0, sha256, digest 0xAA..):
        // update_cnt=0x14, selOut{count=1,{000b,03,010000}}, vals{count=1,{32,AA..}}
        let mut body = Vec::new();
        body.extend_from_slice(&0x14u32.to_be_bytes()); // update_cnt
        body.extend_from_slice(&1u32.to_be_bytes()); // pcrSelectionOut count
        body.extend_from_slice(&[0x00, 0x0B, 0x03, 0x01, 0x00, 0x00]); // selection
        body.extend_from_slice(&1u32.to_be_bytes()); // pcrValues count
        body.extend_from_slice(&32u16.to_be_bytes()); // digest size
        body.extend_from_slice(&[0xAAu8; 32]); // digest
        let r = parse_pcr_read(&body).unwrap();
        assert_eq!(r.update_counter, 0x14);
        assert_eq!(r.values.len(), 1);
        assert_eq!(r.values[0].digest, vec![0xAAu8; 32]);
    }

    #[test]
    fn parse_pcr_read_two_values() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes()); // selection count
        body.extend_from_slice(&[0x00, 0x0B, 0x03, 0x03, 0x00, 0x00]); // PCRs 0,1
        body.extend_from_slice(&2u32.to_be_bytes()); // 2 digests
        body.extend_from_slice(&32u16.to_be_bytes());
        body.extend_from_slice(&[0x11u8; 32]);
        body.extend_from_slice(&32u16.to_be_bytes());
        body.extend_from_slice(&[0x22u8; 32]);
        let r = parse_pcr_read(&body).unwrap();
        assert_eq!(r.values.len(), 2);
        assert_eq!(r.values[0].digest, vec![0x11u8; 32]);
        assert_eq!(r.values[1].digest, vec![0x22u8; 32]);
    }

    #[test]
    fn test_parse_get_capability_property() {
        // more_data(0) + subcap_id(00000006) + count(00000001)
        // + entry {property_id(00000016), value(41424344 = "ABCD")}.
        let mut body = vec![0x00u8]; // more_data
        body.extend_from_slice(&6u32.to_be_bytes()); // subcap_id = TPM_PROPERTIES
        body.extend_from_slice(&1u32.to_be_bytes()); // count
        body.extend_from_slice(&0x16u32.to_be_bytes()); // property (MANUFACTURER)
        body.extend_from_slice(&0x41424344u32.to_be_bytes()); // value = "ABCD"
        let v = parse_get_capability_property(&body).unwrap();
        assert_eq!(v, 0x41424344);
    }

    #[test]
    fn get_capability_real_fixture() {
        // Captured response body for properties-fixed (46 props, first = 0x100).
        let hex = "00000000060000002e00000100322e30000000010100000000";
        let body = hex_to_bytes(hex);
        // more_data=0, subcap=6, count=0x2e, entry0 {0x100, 0x322e3000}
        let v = parse_get_capability_property(&body).unwrap();
        assert_eq!(v, 0x322e3000);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
