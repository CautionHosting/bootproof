//! TEMP probe: decode a captured live SEV-SNP report with the sev crate.
use std::io::Cursor;
use sev::firmware::guest::AttestationReport;
use sev::parser::Decoder;

fn main() {
    let path = std::env::args().nth(1).expect("usage: probe <report> <nonce>");
    let nzpath = std::env::args().nth(2).expect("usage: probe <report> <nonce>");
    let rep = std::fs::read(&path).expect("read report");
    let nz = std::fs::read(&nzpath).expect("read nonce");
    println!("report len = {}", rep.len());
    let ar = AttestationReport::decode(&mut Cursor::new(&rep), ()).expect("decode");
    println!("version    = {}", ar.version);
    println!("policy     = 0x{:x}", ar.policy.0);
    println!("debug_allowed = {}", ar.policy.debug_allowed());
    println!("smt_allowed   = {}", ar.policy.smt_allowed());
    println!("page_swap_dis = {}", ar.policy.page_swap_disabled());
    println!("vmpl       = {}", ar.vmpl);
    println!("signing_key= {}", ar.key_info.signing_key());
    println!("tsme       = {}", ar.plat_info.tsme_enabled());
    println!("report_data matches nonce = {}", ar.report_data.as_slice() == nz.as_slice());
    if ar.report_data.as_slice() != nz.as_slice() {
        println!("  rd = {:?}", &ar.report_data[..16]);
        println!("  nz = {:?}", &nz[..16]);
    }
}
