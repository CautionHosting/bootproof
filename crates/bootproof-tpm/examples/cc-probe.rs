//! Command-code probe: for each contested TPM_CC, ask the firmware via
//! GetCapability(TPM_CAP_CC, subCap=cc, limit=1) whether it advertises that
//! exact code. This is the authoritative ground truth for the CC question.
//!
//! Usage: cargo run -p bootproof-tpm --example cc-probe -- <tcp-addr | /dev/tpm0>

use std::path::Path;

use bootproof_tpm::{Command, Tpm, constants::{cap, st}};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Ask the firmware for the first advertised CC >= sub_cap. Returns the
/// (advertised cc, is-command attr) or None if nothing at/above sub_cap.
fn advertised_cc_geq(tpm: &mut Tpm, sub_cap: u32) -> Option<(u32, u8)> {
    let mut cmd = Command::new(cc_code(), st::NO_SESSIONS);
    cmd.push_u32(cap::COMMANDS);
    cmd.push_u32(sub_cap);
    cmd.push_u32(1);
    let raw = tpm.transfer(&cmd.encode()).ok()?;
    // raw: tag u16 | size u32 | rc u32 | moreData u8 | subCap u32 | count u32 | entries
    if raw.len() < 13 {
        return None;
    }
    let body = &raw[10..]; // after tag+size+rc
    // body: moreData u8 | subCap u32 | count u32 | TPML_CC entries
    let count = u32::from_be_bytes([body[5], body[6], body[7], body[8]]) as usize;
    if count == 0 {
        return None;
    }
    let o = 9;
    if body.len() < o + 5 {
        return None;
    }
    let cc = u32::from_be_bytes([body[o], body[o + 1], body[o + 2], body[o + 3]]);
    let attrs = body[o + 4];
    Some((cc, attrs))
}

fn cc_code() -> u16 {
    use bootproof_tpm::constants::cc;
    cc::GET_CAPABILITY
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

    // (label, bootproof base cc value, spec value) -- spec values from
    // tpm2-tss tss2_tpm2_types.h / ms-tpm-20-ref.
    let contested: [(&str, u32, u32); 10] = [
        ("CreatePrimary", 0x0135, 0x0131),
        ("ReadPublic",    0x016A, 0x0173),
        ("Hash",          0x0160, 0x017D),
        ("PCR_Extend",    0x015C, 0x0182),
        ("NV_ReadPublic", 0x01C9, 0x0169),
        ("Quote",         0x0158, 0x0158),
        ("Sign",          0x015D, 0x015D),
        ("GetCapability", 0x017A, 0x017A),
        ("Startup",       0x0144, 0x0144),
        ("GetRandom",     0x017B, 0x017B),
    ];

    println!("=== GetCapability(COMMANDS) per contested CC ===");
    println!("  {:<14} {:>8} {:>8}  {:<10}  firmware-advertised?",
        "label", "bootproof", "spec", "match");
    for (label, bp, spec) in &contested {
        // Query for the SPEC code first (authoritative), then the bootproof one.
        let spec_advert = advertised_cc_geq(&mut tpm, *spec);
        let bp_advert = if *bp != *spec {
            advertised_cc_geq(&mut tpm, *bp)
        } else {
            spec_advert
        };
        let spec_hit = spec_advert.map(|(c, _)| c == *spec).unwrap_or(false);
        let bp_hit = bp_advert.map(|(c, _)| c == *bp).unwrap_or(false);
        println!(
            "  {:<14} 0x{:04X}   0x{:04X}   {:<10}  spec=0x{:04X}:{:}  bootproof=0x{:04X}:{:}",
            label,
            bp,
            spec,
            if spec_hit { "SPEC-OK" } else { "?" },
            spec,
            spec_hit,
            bp,
            bp_hit,
        );
        // Dump the raw probe for the spec code for the record.
        let mut cmd = Command::new(cc_code(), st::NO_SESSIONS);
        cmd.push_u32(cap::COMMANDS);
        cmd.push_u32(*spec);
        cmd.push_u32(1);
        if let Ok(resp) = tpm.transfer(&cmd.encode()) {
            println!("      raw(spec 0x{:04X}) = {}", spec, hex(&resp));
        }
    }
}
