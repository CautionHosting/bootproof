//! NSM AK-binding witness: exercise the FULL produce->verify bundle
//! round-trip for the `nsm_doc` anchor against a live (sw)TPM, covering
//! the arms the hardware-free unit tests cannot reach at the BUNDLE
//! level. The live PROVEN end-to-end leg (genuine AWS-signed doc naming
//! the run's AK) exists only on NitroTPM hardware (CAST-3); every OTHER
//! arm is witnessed here, including the security-critical ones:
//!
//! 1. opt-out channel (no `with_nsm_scratch`) -> collect NEVER touches
//!    the scratch index (NV byte-unchanged after a full attestation);
//!    the bundle carries no anchor; the fact is the honest Absent
//!    spelling. This is the non-Nitro platform's exact configuration.
//! 2. opted-in channel, scratch index DEFINED (the platform-prepared
//!    state) -> on non-Nitro firmware the vendor leg fails and degrades
//!    to honest absence: collect succeeds anyway, the quote is still
//!    green, still NO anchor, no panic, no channel error.
//! 3. forged bundle: the REAL AWS-signed fixture doc (nsm-live.cbor)
//!    inserted as the bundle's `nsm_doc` anchor -> `verify_bundle` must
//!    land the `nsm_ak_binding` fact NOT PROVEN with the loud FAILED
//!    spelling (wrong nonce / expired window / null-key: ANY reason),
//!    NEVER a silent pass and NEVER the Absent spelling. The quote's
//!    own facts must stay green: the forged identity is rejected at the
//!    binding layer, not by breaking the quote.
//! 4. tampered anchor: one doc byte flipped -> still Failed with a
//!    reason (a mutated COSE doc is not a free pass either).
//!
//! Absent vs Failed at the fact layer is the belt condition: arms 1/2
//! (absent) and 3/4 (failed) must show structurally different fact
//! VALUES, both NOT PROVEN, neither ever Proven.
//!
//! Usage: cargo run -p bootproof --example nsm-ak-bind-witness -- <tcp-addr>
//!
//! State preparation uses tpm2-tools against the SAME tpm (the swtpm
//! socket backend serves ONE connection at a time, so every Tpm here is
//! dropped before the next tool call -- the ek-cert witness's lesson).

use bootproof::channel::{Channel, NsmBinding};
use bootproof::engine::{produce, verify_bundle, VerifyPolicy, VerifierRegistry};
use bootproof::attest::tpm2::Tpm2;
use bootproof::verify::tpm2::Tpm2Verifier;
use bootproof::wire::{B64, Status};
use std::sync::Arc;

/// The live NitroTPM document captured by the sdk: REAL AWS signature,
/// REAL chain to the baked root. In this witness it plays the forgery's
/// payload -- genuine vendor bytes claiming a context they do not belong
/// to (a replay, exactly what an attacker could resubmit).
const NSM_LIVE: &[u8] =
    include_bytes!("../../bootproof-sdk/src/format/data/nsm-live.cbor");

/// The scratch index the platform pre-defines (lower 24 bits; the NSM
/// path ORs in NV_HANDLE_BASE 0x01000000). 0x42 chosen to avoid the
/// witness EK index 0x01C00002 from the ek-cert witness.
const SCRATCH: u32 = 0x0100_0042;
const SCRATCH_HANDLE: &str = "0x01000042";

fn run(cmd: &str, tcti: &str) -> bool {
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
        .expect("usage: nsm-ak-bind-witness <tcp-addr> e.g. 127.0.0.1:2341");
    let (host, port) = addr.rsplit_once(':').expect("addr must be host:port");
    let tcti = format!("swtpm:host={host},port={port}");

    // Defensive flush (learned live 2026-11-09): a panicked earlier run
    // dies before flush_context, and the leaked transient contexts
    // exhaust the tiny swtpm pool -- the next run's Quote then fails
    // with a handle-side error that has nothing to do with the arms.
    let _ = run("tpm2_flushcontext -t; tpm2_flushcontext -s", &tcti);

    // Idempotent scratch state: define the index the platform would
    // pre-define (owner auth, AUTHREAD|AUTHWRITE per NV_ATTRS_AUTH_RW
    // 0x0004_0004). Size note: production NV_SIZE is 8192 (attest.rs),
    // but this witness swtpm caps TPM2_PT_NV_INDEX_MAX at 0x800 (2048,
    // measured 2026-11-09), so the index here is 2048. The arms never
    // depend on the content or size: they check byte-equality of NV
    // before/after and the presence/absence of the anchor. On NitroTPM
    // the platform defines the full 8192.
    let _ = run(
        &format!("tpm2_nvundefine -C o {SCRATCH_HANDLE} 2>/dev/null"),
        &tcti,
    );
    assert!(
        run(
            &format!("tpm2_nvdefine -C o -a 0x00040004 -s 2048 {SCRATCH_HANDLE}"),
            &tcti
        ),
        "the witness TPM must define the scratch index"
    );

    let nonce = [0x11u8; 32];
    let mut registry = VerifierRegistry::new();
    registry.register(Box::new(Tpm2Verifier));
    let policy = VerifyPolicy::default_policy();

    // -- Arm 1: opt-out channel. The non-Nitro configuration: no scratch
    //    index ever configured, NV never written, no anchor, honest
    //    absence. Byte-proof of "never touched": NV content before and
    //    after must match.
    let before = {
        let mut tpm = bootproof_tpm::Tpm::connect_swtpm_tcp_started(&addr).expect("connect");
        bootproof_tpm::nv::nv_read_index(&mut tpm, SCRATCH).ok()
    };
    let ch1: Arc<Vec<Box<dyn Channel + Send + Sync>>> = Arc::new(vec![Box::new(
        Tpm2::new("/dev/tpm0").with_tcp(addr.clone()),
    )]);
    let b1 = produce(&nonce, "witness-node", "witness", &ch1, Vec::new());
    let after = {
        let mut tpm = bootproof_tpm::Tpm::connect_swtpm_tcp_started(&addr).expect("connect");
        bootproof_tpm::nv::nv_read_index(&mut tpm, SCRATCH).ok()
    };
    assert_eq!(before, after, "arm1: an opted-out channel must not touch NV");
    let no_anchor = b1
        .evidence
        .iter()
        .find(|e| e.channel == "tpm2")
        .map(|e| !e.anchors.contains_key("nsm_doc"))
        .unwrap_or(false);
    assert!(no_anchor, "arm1: no nsm_doc anchor without opt-in");
    let v1 = verify_bundle(&b1, &policy, &registry);
    let f1 = v1
        .facts
        .iter()
        .find(|f| f.name == "nsm_ak_binding")
        .expect("arm1: the fact is never dropped");
    assert_eq!(f1.status, Status::NotProven);
    assert!(
        f1.value.starts_with("absent:"),
        "arm1: honest absence spelling, got {}",
        f1.value
    );
    println!("arm1 opt-out        -> NV untouched, no anchor, fact absent: OK");

    // -- Arm 2: opted-in channel on non-Nitro firmware, scratch DEFINED.
    //    The vendor leg must fail and degrade: collect succeeds, quote
    //    green, still no anchor, no channel error. (On NitroTPM this
    //    same configuration produces the anchor: the CAST-3 live leg.)
    let ch2: Arc<Vec<Box<dyn Channel + Send + Sync>>> = Arc::new(vec![Box::new(
        Tpm2::new("/dev/tpm0")
            .with_tcp(addr.clone())
            .with_nsm_scratch(SCRATCH),
    )]);
    let b2 = produce(&nonce, "witness-node", "witness", &ch2, Vec::new());
    let ev2 = b2
        .evidence
        .iter()
        .find(|e| e.channel == "tpm2")
        .expect("arm2: the tpm2 channel produced");
    assert!(
        !ev2.anchors.contains_key("nsm_doc"),
        "arm2: non-Nitro firmware must degrade to no-anchor"
    );
    let v2 = verify_bundle(&b2, &policy, &registry);
    assert!(
        !v2.errors.iter().any(|e| e.starts_with("tpm2:")),
        "arm2: a vendor-leg failure must not error the channel: {:?}",
        v2.errors
    );
    let f2 = v2
        .facts
        .iter()
        .find(|f| f.name == "nsm_ak_binding")
        .expect("arm2: the fact is never dropped");
    assert!(f2.value.starts_with("absent:"), "arm2: absence spelling");
    println!("arm2 opt-in non-Nitro -> vendor leg degrades, quote green: OK");

    // -- Arm 3: forged bundle. Real AWS-signed bytes as the anchor, in a
    //    bundle whose quote was made for a different nonce with a
    //    different AK. verify_bundle must fail the binding CLOSED with
    //    the FAILED spelling (never the Absent spelling, never Proven),
    //    while the quote's own facts stay green.
    let mut b3 = b1.clone();
    {
        let ev = b3
            .evidence
            .iter_mut()
            .find(|e| e.channel == "tpm2")
            .expect("arm3: tpm2 evidence");
        ev.anchors
            .insert("nsm_doc".into(), B64::new(NSM_LIVE.to_vec()));
    }
    let v3 = verify_bundle(&b3, &policy, &registry);
    let f3 = v3
        .facts
        .iter()
        .find(|f| f.name == "nsm_ak_binding")
        .expect("arm3: the fact is never dropped");
    assert_eq!(f3.status, Status::NotProven);
    assert!(
        f3.value.contains("present but FAILED"),
        "arm3: present-but-bad must be the FAILED spelling, got {}",
        f3.value
    );
    assert_ne!(
        f3.value, f1.value,
        "arm3: Failed must be structurally distinct from Absent"
    );
    let quote_ok = v3
        .facts
        .iter()
        .any(|f| f.name == "tpm_quote" && f.status == Status::Proven);
    assert!(
        quote_ok,
        "arm3: the forged identity must not break the quote's own checks: {:?}",
        v3.errors
    );
    println!("arm3 forged anchor  -> fact FAILED loudly, quote stays green: OK");

    // -- Arm 4: tampered anchor. One flipped doc byte: the COSE/payload
    //    parse or signature must reject, still Failed with a reason.
    let mut tampered = NSM_LIVE.to_vec();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    let mut b4 = b1.clone();
    {
        let ev = b4
            .evidence
            .iter_mut()
            .find(|e| e.channel == "tpm2")
            .expect("arm4: tpm2 evidence");
        ev.anchors.insert("nsm_doc".into(), B64::new(tampered));
    }
    let v4 = verify_bundle(&b4, &policy, &registry);
    let f4 = v4
        .facts
        .iter()
        .find(|f| f.name == "nsm_ak_binding")
        .expect("arm4: the fact is never dropped");
    assert!(
        f4.value.contains("present but FAILED"),
        "arm4: tampered doc must FAIL with a reason, got {}",
        f4.value
    );
    println!("arm4 tampered anchor -> Failed with reason: OK");

    // Cross-arm belt check: the decision states themselves are distinct
    // (Absent != Failed("")), and nothing anywhere said Proven.
    assert_ne!(NsmBinding::Absent, NsmBinding::Failed(String::new()));
    for (tag, v) in [("arm1", &v1), ("arm2", &v2), ("arm3", &v3), ("arm4", &v4)] {
        let f = v.facts.iter().find(|f| f.name == "nsm_ak_binding");
        assert!(
            f.map(|f| f.status != Status::Proven).unwrap_or(true),
            "{tag}: never Proven without the genuine live binding"
        );
    }

    // Leave the scratch index for reruns (idempotent redefine above).
    println!("ALL ARMS PASS");
}
