//! `bootproof tpm-probe`: a debug command that talks to a local TPM and
//! prints PCRs + device properties. Used to validate the raw TPM2 client
//! against `tpm2_pcrread` / `tpm2_getcap` ground truth.

use anyhow::{Context, Result};

use bootproof_tpm::{PcrSelection, Tpm, constants::alg};

// TPM_PT property IDs (TPM2_PT_FIXED = 0x0100 base), per the kernel
// `TPM2_PT_*` definitions and captured `tpm2_getcap properties-fixed`.
const TPM20_PROPS: [(u32, &str); 5] = [
    (0x0000_0105, "manufacturer"),
    (0x0000_0106, "vendor_string_1"),
    (0x0000_0107, "vendor_string_2"),
    (0x0000_0108, "vendor_string_3"),
    (0x0000_010B, "firmware_version_1"),
];

/// Run the probe against an already-connected, started TPM.
pub fn run(mut tpm: Tpm, pcrs: Option<Vec<u8>>, source: &str) -> Result<()> {
    println!("== bootproof tpm-probe ==  source={source}");

    let indices: Vec<u8> = match pcrs {
        Some(p) if !p.is_empty() => p,
        _ => (0..24).collect(),
    };

    // SHA-256 PCR values.
    let res = tpm
        .pcr_read(&[PcrSelection::new(alg::SHA256, &indices)])
        .context("TPM2_PCR_Read")?;

    println!("== PCR read (sha256) ==  update_counter={}", res.update_counter);
    for (i, v) in res.values.iter().enumerate() {
        // Values come back in request order; map back to the requested index.
        let requested = indices.get(i).copied().unwrap_or(i as u8);
        println!("  PCR{requested:>2}  {}", hex_str(&v.digest));
    }

    // SHA-384 PCR values (the image-hash PCR is typically sha384).
    let res384 = tpm
        .pcr_read(&[PcrSelection::new(alg::SHA384, &indices)])
        .context("TPM2_PCR_Read sha384")?;
    println!("== PCR read (sha384) ==  update_counter={}", res384.update_counter);
    for (i, v) in res384.values.iter().enumerate() {
        let requested = indices.get(i).copied().unwrap_or(i as u8);
        println!("  PCR{requested:>2}  {}", hex_str(&v.digest));
    }

    // Device properties. Values are u32 encoding four ASCII chars (e.g. the
    // TPM manufacturer "IBM " = 0x49424D20).
    println!("== properties ==");
    for (pt, name) in TPM20_PROPS {
        match tpm.get_property(pt) {
            Ok(v) => {
                let b = v.to_be_bytes();
                let s: String = b
                    .iter()
                    .map(|x| if x.is_ascii_alphanumeric() { *x as char } else { '.' })
                    .collect();
                println!("  {name:<20} {s}  (0x{v:08X})");
            }
            Err(e) => println!("  {name:<20} <error: {e}>"),
        }
    }

    Ok(())
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
