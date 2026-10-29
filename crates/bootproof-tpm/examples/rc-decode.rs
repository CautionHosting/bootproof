fn main() {
    let code = std::env::args().nth(1).unwrap_or_else(|| "0x09A2".into());
    let n = u32::from_str_radix(code.trim_start_matches("0x"), 16).unwrap();
    println!("{code} = 0x{n:08x}  ->  {}", bootproof_tpm::esys::decode_rc(n));
    // also show the format-bit breakdown
    let p = (n >> 15) & 1;
    let fmt = (n >> 10) & 3;
    let idx = n & 0x00F;
    let hp = (n >> 4) & 1;
    println!("  P={} fmt={} idx={} H/P={} (1=param,0=handle)", p, fmt, idx, hp);
}
