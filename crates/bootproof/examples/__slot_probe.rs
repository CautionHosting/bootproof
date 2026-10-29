use sha2::Digest;
fn main() {
    use bootproof_tpm::Tpm;
    let mut t = Tpm::connect_swtpm_tcp_started("127.0.0.1:24421").expect("connect");
    let all = bootproof_tpm::PcrSelection::all(bootproof_tpm::constants::alg::SHA256);
    let disc = t.pcr_read(&[all]).expect("discover");
    let avail = disc.selection.map(|s| s.indices()).unwrap_or_default();
    println!("available PCRs: {:?}", avail);
    for p in [16u32,17,21,22,23] {
        let rs: String = match t.pcr_reset(p) {
            Ok(()) => "R".into(),
            Err(e) => e.to_string().split_whitespace().next().unwrap_or("?").into(),
        };
        let ex = if t.pcr_extend(p, &[1u8;32]).is_ok() { "E" } else { "x" };
        println!("pcr{p:2}: reset={rs:>8}  extend={ex}");
    }
    if t.pcr_reset(22).is_ok() {
        let d = sha2::Sha256::digest(b"docs").to_vec();
        t.pcr_extend(22, &d).expect("extend 22");
        let sel = bootproof_tpm::PcrSelection::new(bootproof_tpm::constants::alg::SHA256, &[22]);
        let r = t.pcr_read(&[sel]).expect("read 22");
        let actual = r.values[0].digest.clone();
        let mut m = Vec::new(); m.extend_from_slice(&[0u8;32]); m.extend_from_slice(&d);
        let expected = sha2::Sha256::digest(&m).to_vec();
        println!("determinism: PCR22 after reset+extend == H(0||D): {}", actual == expected);
    } else {
        println!("pcr22 reset not allowed here");
    }
}
