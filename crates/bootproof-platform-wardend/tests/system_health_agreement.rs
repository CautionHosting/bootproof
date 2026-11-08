// The wardend channel's half of the two-verifiers-agree gate: the SAME
// golden fixture envelope the core test (crates/bootproof/tests/
// system_health_agreement.rs) pins for snp + tpm2, verified here for the
// wardend channel by BOTH verifiers:
//
//   * Rust: WardendVerifier (this plugin) through engine::verify_bundle.
//   * JS:   the service worker verify.js checkStateLog, via
//     fixtures/system_health/harness.js (node + WebCrypto).
//
// The golden must agree EXACTLY (wardend_state_chain PROVEN on both
// sides, and the Rust seal-state/pcr-policy facts must not contradict the
// JS seal_state sub). The log-tamper must be REJECTED by both, through
// the documented mapping: the plugin errors the wardend channel with the
// honest NOT PROVEN failed-fact; the JS rolls wardend_state_chain to
// FAILED.
use bootproof::engine::{verify_bundle, VerifierRegistry, VerifyPolicy};
use bootproof::wire::{Bundle, Status};
use bootproof_platform_wardend::WardendVerifier;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/system_health")
}

/// The typed-schema gate (the fixture-vs-schema drift killer, same rule as
/// the core agreement test): decode a fixture through the REAL
/// `system_health::schema::Envelope` BEFORE the verdict crosswalk runs, so
/// no fixture can drift from the presentation schema unnoticed. Also
/// assert the schema-declared `identity.leaf_pem_present` key explicitly:
/// the schema leniently defaults that field, so a bare typed decode would
/// not catch an omission.
fn typed_envelope(fixture: &Path) -> bootproof::system_health::schema::Envelope {
    let text = std::fs::read_to_string(fixture)
        .unwrap_or_else(|e| panic!("read {}: {e}", fixture.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("{} is not a valid schema::Envelope: {e}", fixture.display())
    })
}

fn assert_identity_leaf_claim_explicit(fixture: &Path, expected: bool) {
    let text = std::fs::read_to_string(fixture).expect("fixture readable");
    let v: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
    let claim = v
        .get("identity")
        .expect("identity section")
        .get("leaf_pem_present");
    assert_eq!(
        claim.and_then(|x| x.as_bool()),
        Some(expected),
        "{}: identity.leaf_pem_present must be the explicit {expected}",
        fixture.display()
    );
}

/// Verify ONLY the wardend channel (this plugin's scope) with the engine.
fn rust_wardend_facts(fixture: &Path) -> (BTreeMap<String, String>, Vec<String>) {
    // The typed-schema gate runs FIRST (every fixture, typed, before any
    // verdict is derived).
    let _ = typed_envelope(fixture);
    assert_identity_leaf_claim_explicit(fixture, false);
    let text = std::fs::read_to_string(fixture)
        .unwrap_or_else(|e| panic!("read {}: {e}", fixture.display()));
    let env: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
    let bundle: Bundle =
        serde_json::from_value(env.get("bundle").cloned().expect("bundle")).expect("bundle");
    let mut reg = VerifierRegistry::new();
    reg.register(Box::new(WardendVerifier));
    let vf = verify_bundle(&bundle, &VerifyPolicy::default_policy(), &reg);
    let mut map = BTreeMap::new();
    for f in &vf.facts {
        map.insert(f.name.clone(), status_str(f.status).to_string());
    }
    // This registry owns ONLY the wardend channel: "no verifier" errors
    // for the other channels are expected scope, not failures.
    let wardend_errors: Vec<String> = vf
        .errors
        .into_iter()
        .filter(|e| e.starts_with("wardend:") || e.contains("channel wardend"))
        .collect();
    (map, wardend_errors)
}

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Proven => "PROVEN",
        Status::Reproducible => "REPRODUCIBLE",
        Status::Degraded => "DEGRADED",
        Status::NotProven => "NOT PROVEN",
    }
}

/// The JS side: the harness (the REAL verify.js) on the same fixture.
fn js_facts(fixture: &Path) -> BTreeMap<String, String> {
    let out = Command::new("node")
        .arg(fixtures_dir().join("harness.js"))
        .arg(fixture)
        .output()
        .expect("node runs the harness (node is part of the test environment)");
    assert!(
        out.status.success(),
        "harness failed on {}: {}",
        fixture.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("harness JSON");
    let mut map = BTreeMap::new();
    for f in v.get("facts").and_then(|a| a.as_array()).expect("facts") {
        map.insert(
            f.get("name").and_then(|n| n.as_str()).expect("name").to_string(),
            f.get("status").and_then(|s| s.as_str()).expect("status").to_string(),
        );
    }
    map
}

/// The golden: exact agreement on wardend_state_chain (PROVEN both sides).
#[test]
fn golden_wardend_agreement() {
    let g = fixtures_dir().join("golden.json");
    let (rust, errors) = rust_wardend_facts(&g);
    assert!(errors.is_empty(), "the golden wardend channel must verify clean: {errors:?}");
    let js = js_facts(&g);
    assert_eq!(
        rust.get("wardend_state_chain").map(String::as_str),
        Some("PROVEN"),
        "rust wardend_state_chain: {rust:?}"
    );
    assert_eq!(
        js.get("wardend_state_chain").map(String::as_str),
        Some("PROVEN"),
        "js wardend_state_chain must agree exactly on the golden"
    );
    // The companion facts the same channel check must not contradict the
    // JS roll: the seal state and the PCR policy coverage are PROVEN on
    // the Rust side (the JS side renders them as metadata, not facts).
    assert_eq!(rust.get("wardend_seal_state").map(String::as_str), Some("PROVEN"));
    assert_eq!(rust.get("wardend_pcr_policy").map(String::as_str), Some("PROVEN"));
}

/// The log tamper: BOTH verifiers reject the flipped wardend log, through
/// the documented mapping (Rust: the channel errors with the honest NOT
/// PROVEN failed-fact named "wardend"; JS: wardend_state_chain FAILED).
#[test]
fn log_tamper_rejected_by_both() {
    let g = fixtures_dir().join("golden.log-tamper.json");
    let (rust, errors) = rust_wardend_facts(&g);
    assert!(
        errors.iter().any(|e| e.starts_with("wardend:")),
        "rust must error the tampered wardend channel: {errors:?}"
    );
    let me = rust.get("wardend").map(String::as_str);
    assert_eq!(me, Some("NOT PROVEN"), "the failed-fact is the honest NOT PROVEN: {rust:?}");
    let js = js_facts(&g);
    assert_eq!(
        js.get("wardend_state_chain").map(String::as_str),
        Some("FAILED"),
        "js must roll wardend_state_chain to FAILED on the same tamper"
    );
}
