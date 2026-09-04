//! Probe: capture ground-truth name / public / qualifiedSigner from a live TPM.
//!
//! Usage: cargo run -p bootproof-tpm --example qname-probe -- <tcp-addr | /dev/tpm0>
//!
//! Creates the same ECC P-256 primary the tpm2 channel uses
//! (create_primary_ecc_sign, hierarchy 0x4000_0001), then a Quote, and dumps
//! the TPM-returned name, the marshalled public, and the attestation's
//! qualifiedSigner so the qualified-name formula can be validated offline.

use std::path::Path;

use bootproof_tpm::{PcrSelection, Result, Tpm, constants::alg};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> Result<()> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/dev/tpm0".into());
    let mut tpm = if target.starts_with('/') {
        Tpm::open_started(Path::new(&target))?
    } else {
        Tpm::connect_swtpm_tcp_started(&target)?
    };

    let key = tpm.create_primary_ecc_sign()?;
    println!("public_len = {}", key.public.len());
    println!("public     = {}", hex(&key.public));
    println!("name       = {}", hex(&key.name));

    let nonce = [0x42u8; 16];
    let q = tpm.quote(&key, &nonce, &[PcrSelection::new(alg::SHA256, &[0])])?;
    let att = &q.attestation;
    // TPMS_ATTEST: magic(4) type(2) qualifiedSigner(TPM2B @6)
    let qs_size = u16::from_be_bytes([att[6], att[7]]) as usize;
    let qs = &att[8..8 + qs_size];
    println!("qual_signer = {}", hex(qs));
    Ok(())
}
