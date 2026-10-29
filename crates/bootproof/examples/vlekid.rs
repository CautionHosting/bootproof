use sev::certs::snp::Verifiable;
fn main() {
    let pem = std::fs::read_to_string("/tmp/snpwork/live-vlek.pem").unwrap();
    use base64::Engine as _;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<String>().replace(" ", "");
    let der = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    let cert = x509_parser::parse_x509_certificate(&der).unwrap().1;
    println!("CN={:?}", cert.subject().iter_common_name().next().unwrap().as_str());
    for ext in cert.extensions() {
        println!("ext oid: {}", ext.oid.to_string());
    }
    let sev = sev::certs::snp::Certificate::from_pem(pem.as_bytes()).unwrap();
    let ark = sev::certs::snp::Certificate::from_pem(include_bytes!("../src/trust/data/ark-milan.pem")).unwrap();
    let asvk = sev::certs::snp::Certificate::from_pem(include_bytes!("../src/trust/data/asvk-sev-vlek-milan.pem")).unwrap();
    let chain = sev::certs::snp::Chain { ca: sev::certs::snp::ca::Chain { ark, ask: asvk }, vek: sev };
    println!("LIVE VLEK chains to pinned ARK-Milan: {}", chain.verify().is_ok());
}
