//! Ground-truth capability probe: dump the firmware's own algorithm and
//! handle capability bytes so the "StageX dialect" question can be settled
//! from evidence, not assumption.
//!
//! Usage: cargo run -p bootproof-tpm --example cap-probe -- <tcp-addr | /dev/tpm0>
//!
//! Emits:
//!   1. GetCapability(TPM_ALG) full enumeration (all supported algorithm IDs).
//!   2. GetCapability(TPM_ALG, subCap=0x0043) exactly as detect_dialect sends
//!      it, with the returned entries decoded (to show whether "count>0"
//!      really means an algorithm at 0x0043 or just the next one up).
//!   3. GetCapability(TPMI_CAP_HANDLES, TPM_RH) -- every permanent handle
//!      the firmware exposes.
//!   4. Vendor / family / firmware-version TPM properties.

use std::path::Path;

use bootproof_tpm::{Command, Tpm, constants::{alg, cap, st}};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read_u16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([b[o], b[o + 1]]))
}
fn read_u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]))
}

/// GetCapability(TPM_ALG, subCap) -> (more_data, Vec<(alg_id, digest_size, selectable)>).
fn cap_algs(tpm: &mut Tpm, sub_cap: u32, limit: u32) -> (u8, Vec<(u16, u16, u8)>) {
    let mut cmd = Command::new(constants_cc(), st::NO_SESSIONS);
    cmd.push_u32(cap::ALGS);
    cmd.push_u32(sub_cap);
    cmd.push_u32(limit);
    let (_rc, body) = tpm.call(&cmd).expect("GetCapability(ALG) failed");
    // body: moreData u8 | subCap u32 | count u32 | entries (TPM_ALG_PROPERTY:
    // alg u16 | algDigestSize u16 | isSelectable u8)
    let more = body[0];
    let count = read_u32(&body, 5).expect("truncated") as usize;
    let mut out = Vec::new();
    for i in 0..count {
        let o = 9 + i * 5;
        let a = read_u16(&body, o).expect("truncated");
        let d = read_u16(&body, o + 2).expect("truncated");
        let s = body[o + 4];
        out.push((a, d, s));
    }
    (more, out)
}

/// GetCapability(TPMI_CAP_HANDLES, htype) -> (more_data, Vec<handle>).
fn cap_handles(tpm: &mut Tpm, htype: u32) -> (u8, Vec<u32>) {
    let mut cmd = Command::new(constants_cc(), st::NO_SESSIONS);
    cmd.push_u32(cap::HANDLES);
    cmd.push_u32(htype);
    cmd.push_u32(0xFFFF_FFFF);
    let (_rc, body) = tpm.call(&cmd).expect("GetCapability(HANDLES) failed");
    let more = body[0];
    let count = read_u32(&body, 5).expect("truncated") as usize;
    let mut out = Vec::new();
    for i in 0..count {
        out.push(read_u32(&body, 9 + i * 4).expect("truncated"));
    }
    (more, out)
}

/// GetCapability(TPM_PROPERTIES, tpm_pt, 1) -> u32 value.
fn cap_property(tpm: &mut Tpm, tpm_pt: u32) -> Option<u32> {
    let mut cmd = Command::new(constants_cc(), st::NO_SESSIONS);
    cmd.push_u32(cap::TPM_PROPERTIES);
    cmd.push_u32(tpm_pt);
    cmd.push_u32(1);
    match tpm.call(&cmd) {
        Ok((_rc, body)) => {
            // body: moreData u8 | property u32 | count u32 | values
            if body.len() >= 13 {
                read_u32(&body, 9)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn constants_cc() -> u16 {
    // TPM_CC_GetCapability = 0x017A in the spec; the crate's own constant is
    // cc::GET_CAPABILITY.
    use bootproof_tpm::constants::cc;
    cc::GET_CAPABILITY
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/dev/tpm0".into());
    let mut tpm = if target.starts_with('/') {
        Tpm::open_started(Path::new(&target)).expect("open")
    } else {
        Tpm::connect_swtpm_tcp_started(&target).expect("connect")
    };

    println!("=== 1. GetCapability(TPM_ALG) full enumeration ===");
    let mut sub: u32 = 0;
    let mut more = 1u8;
    let mut all: Vec<(u16, u16, u8)> = Vec::new();
    while more != 0 && sub < 0x100 {
        let (m, entries) = cap_algs(&mut tpm, sub, 0xFFFF);
        more = m;
        if entries.is_empty() {
            break;
        }
        for e in &entries {
            println!("  alg=0x{:04X} digestSize={} selectable={}", e.0, e.1, e.2);
        }
        let last = *entries.last().unwrap();
        all.extend(entries);
        sub = last.0.saturating_add(1) as u32;
    }
    let has_0x43 = all.iter().any(|(a, _, _)| *a == 0x0043);
    let has_0x45 = all.iter().any(|(a, _, _)| *a == 0x0045);
    let cfb_at = all.iter().find(|(a, _, _)| *a == 0x0042).map(|_| true);
    println!("  --> algorithm at 0x0043 present: {}", has_0x43);
    println!("  --> algorithm at 0x0045 present: {}", has_0x45);
    println!("  --> algorithm at 0x0042 present: {}", cfb_at.unwrap_or(false));

    println!();
    println!("=== 2. detect_dialect probe: GetCapability(TPM_ALG, subCap=0x0043, limit=1) ===");
    let (more2, entries2) = cap_algs(&mut tpm, alg::CFB as u32, 1);
    println!(
        "  raw response: moreData={} count={} entries=[{}]",
        more2,
        entries2.len(),
        entries2
            .iter()
            .map(|(a, d, s)| format!("0x{:04X}({}B,sel={})", a, d, s))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  --> detect_dialect() would set dialect = {}",
        entries2.len() > 0
    );
    if let Some((a, _, _)) = entries2.first() {
        println!(
            "  --> first returned alg id is 0x{:04X} (== requested 0x0043? {})",
            a,
            *a == 0x0043
        );
    }

    println!();
    println!("=== 3. GetCapability(TPMI_CAP_HANDLES, TPM_RH) ===");
    let (_, handles) = cap_handles(&mut tpm, 0x4000_0000);
    let mut hs = handles.clone();
    hs.sort_unstable();
    for h in &hs {
        let known = match *h {
            0x4000_0001 => "OWNER (spec TPM_RH_OWNER)",
            0x4000_0003 => "ENDORSEMENT (spec TPM_RH_ENDORSEMENT)",
            0x4000_0004 => "PLATFORM (spec TPM_RH_PLATFORM)",
            0x4000_0005 => "OWNER_AUTH (spec)",
            0x4000_0006 => "LOCKOUT_AUTH (spec)",
            0x4000_0007 => "PLATFORM_AUTH (spec)",
            0x4000_0009 => "LOCKOUT (spec TPM_RH_LOCKOUT)",
            0x4000_000A => "LOCKOUT (rh_dialect claims this)",
            0x4000_000B => "ENDORSEMENT (rh_dialect claims this)",
            0x4000_000C => "PLATFORM (rh_dialect claims this)",
            0x4000_0002 => "?? (no spec name at 0x02)",
            other => {
                let _ = other;
                "??"
            }
        };
        println!("  handle 0x{:08X}  {}", h, known);
    }

    println!();
    println!("=== 4. Vendor properties ===");
    // TPM_PT: FAMILY=0x00000001, VENDOR_STRING_1..4=0x000001C1..0x000001C4,
    // VENDOR_UEFI=0x000001C6, FIRMWARE_VERSION_1/2=0x000001C7/0x000001C8.
    let fam = cap_property(&mut tpm, 0x0000_0001);
    println!("  TPM_PT_FAMILY = 0x{:08X?}", fam);
    let mut v = String::new();
    for i in 0..4 {
        if let Some(part) = cap_property(&mut tpm, 0x0000_01C1 + i as u32) {
            let bytes = part.to_be_bytes();
            v.push_str(&cstr(&bytes));
        }
    }
    println!("  TPM_PT_VENDOR_STRING = {:?}", v);
    let mut fw = String::new();
    for i in 0..2 {
        if let Some(part) = cap_property(&mut tpm, 0x0000_01C7 + i as u32) {
            let bytes = part.to_be_bytes();
            fw.push_str(&cstr(&bytes));
        }
    }
    println!("  TPM_PT_FIRMWARE_VERSION = {:?}", fw);
    // Full raw dump of the 0x0043 probe for the record.
    let mut cmd = Command::new(constants_cc(), st::NO_SESSIONS);
    cmd.push_u32(cap::ALGS);
    cmd.push_u32(0x0043);
    cmd.push_u32(1);
    if let Ok(resp) = tpm.transfer(&cmd.encode()) {
        println!();
        println!("  raw probe response bytes: {}", hex(&resp));
    }
}
