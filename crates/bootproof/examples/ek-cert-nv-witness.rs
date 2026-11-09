//! NV EK-cert witness: exercise the shipped `read_ek_cert` against a live
//! (sw)TPM under the three states the field sees:
//!
//! 1. index ABSENT       -> must be None (honest absence)
//! 2. index = junk bytes -> must be None (the X.509 gate rejects fakes;
//!    this is the state the old `read_public_raw` path shipped as a
//!    "cert", so this arm IS the regression tripwire)
//! 3. index = real cert  -> must be Some, byte-identical to what was
//!    written (multi-chunk reads included when the cert exceeds
//!    TPM_PT_NV_BUFFER_MAX)
//!
//! Usage: cargo run -p bootproof --example ek-cert-nv-witness -- <tcp-addr>
//!
//! State preparation uses tpm2-tools (tpm2_nvdefine/tpm2_nvwrite) against
//! the SAME tpm; the read path under test is bootproof's, exclusively.

use bootproof::attest::tpm2::read_ek_cert;
use bootproof_tpm::Tpm;

fn run(cmd: &str, tcti: &str) -> bool {
    // The TCTI env points tpm2-tools at the witness TPM (otherwise they
    // hunt for /dev/tpmrm0 and fail). bash so the openssl subshell forms
    // work unchanged across distros.
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .env("TPM2TOOLS_TCTI", tcti)
        .output()
        .expect("spawn bash");
    let ok = out.status.success();
    if !ok {
        eprintln!(
            "[witness] cmd failed: {cmd}\n  stderr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    ok
}

fn main() {
    let addr = std::env::args()
        .nth(1)
        .expect("usage: ek-cert-nv-witness <tcp-addr> e.g. 127.0.0.1:2341");
    // tpm2-tools reach the witness TPM over the swtpm TCTI: the syntax is
    // `swtpm:host=H,port=P` where P is the DATA port (the plugin dials
    // control at P+1 itself). The default (no host/port) dials 2321, which
    // on this box lands on a neighbor swtpm instance entirely (observed:
    // stale 0x0A9A errors from a different TPM).
    let (host, port) = addr.rsplit_once(':').expect("addr must be host:port");
    let tcti = format!("swtpm:host={host},port={port}");
    // Scratch paths under the process temp dir (no /tmp litter assumptions).
    let tmp = std::env::temp_dir();
    let junk_path = tmp.join("bootproof-ek-junk.bin");
    let cert_pem = tmp.join("bootproof-ek-cert.pem");
    let cert_key = tmp.join("bootproof-ek-key.pem");
    let cert_der = tmp.join("bootproof-ek-cert.der");

    // Make the run idempotent: drop any EK index left by an earlier run
    // (ignore the error when it does not exist).
    let _ = run("tpm2_nvundefine -C o 0x01C00002 2>/dev/null", tcti.as_str());

    // swtpm's socket backend serves ONE data connection at a time: a new
    // connect queues until the previous client disconnects. So the Tpm
    // must be DROPPED before every tpm2-tools staging command (learned
    // live 2026-11-09: holding it open deadlocks the next tool call).

    // -- Arm 1: absent index. A fresh swtpm state has no EK cert index.
    let absent = {
        let mut tpm = Tpm::connect_swtpm_tcp_started(&addr).expect("connect");
        read_ek_cert(&mut tpm)
    };
    println!("arm1 absent  -> {:?}", absent.as_ref().map(Vec::len));
    assert!(absent.is_none(), "absent index must read as None");

    // -- Arm 2: junk bytes at the EK index -> the gate must reject.
    // NOTE the tpm2-tools syntax: `-a` is the TPMA_NV attribute set
    // (OWNERREAD|OWNERWRITE here), the index handle is POSITIONAL.
    assert!(
        run(&format!(
            "echo -n 'not a certificate' > {} && \
             tpm2_nvdefine -C o -s 17 -a 0x00020002 0x01C00002 && \
             tpm2_nvwrite -C o -i {} 0x01C00002",
            junk_path.display(),
            junk_path.display()
        ), tcti.as_str()),
        "failed to stage the junk index"
    );
    let junk = {
        let mut tpm = Tpm::connect_swtpm_tcp_started(&addr).expect("connect");
        read_ek_cert(&mut tpm)
    };
    println!("arm2 junk    -> {:?}", junk.as_ref().map(Vec::len));
    assert!(junk.is_none(), "non-cert bytes must read as None (gate)");

    // -- Arm 3: a real self-signed DER cert -> must come back byte-exact.
    // RSA-4096 keeps the DER over swtpm's 1024-byte NV_BUFFER_MAX (read
    // live via tpm2_getcap: 0x400), so nv_read_index genuinely loops and
    // reassembles multiple chunks. A cert under 1024 would pass the round
    // trip without ever testing the chunking path.
    assert!(
        run(&format!(
            "openssl req -x509 -newkey rsa:4096 \
             -keyout {} -out {} -days 1 -nodes \
             -subj '/CN=bootproof witness EK' 2>/dev/null && \
             openssl x509 -in {} -outform DER -out {}",
            cert_key.display(),
            cert_pem.display(),
            cert_pem.display(),
            cert_der.display()
        ), tcti.as_str()),
        "failed to mint a witness cert"
    );
    let der = std::fs::read(&cert_der).expect("read der");
    // Assert the premise of this arm before trusting it: the cert MUST
    // exceed the chunk cap or the test silently degrades to one read.
    let cap = {
        let mut tpm = Tpm::connect_swtpm_tcp_started(&addr).expect("connect");
        bootproof_tpm::nv::max_nv_buffer(&mut tpm)
    };
    assert!(
        der.len() > cap as usize,
        "witness cert is {} B but the NV chunk cap is {}; not a multi-chunk test",
        der.len(),
        cap
    );
    assert!(
        run(&format!(
            "tpm2_nvundefine -C o 0x01C00002 2>/dev/null; \
             tpm2_nvdefine -C o -s {} -a 0x00020002 0x01C00002 && \
             tpm2_nvwrite -C o -i {} 0x01C00002",
            der.len(),
            cert_der.display()
        ), tcti.as_str()),
        "failed to stage the cert index"
    );
    let got = {
        let mut tpm = Tpm::connect_swtpm_tcp_started(&addr).expect("connect");
        read_ek_cert(&mut tpm)
    }
    .expect("a real DER cert must read as Some");
    println!("arm3 cert    -> {} bytes read, {} written", got.len(), der.len());
    assert_eq!(got, der, "round-tripped cert must be byte-identical");

    // Cleanup: leave the witness TPM as we found it (no EK index).
    let _ = run("tpm2_nvundefine -C o 0x01C00002 2>/dev/null", tcti.as_str());

    println!("ek-cert-nv-witness: ALL ARMS PASS");
}
