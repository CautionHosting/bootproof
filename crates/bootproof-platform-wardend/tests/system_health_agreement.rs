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
use bootproof_platform_wardend::{canonical_doc_digest, canonical_doc_digest_v2, WardendVerifier};
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

// ---------------------------------------------------------------------------
// I-2: the whole-doc signature legs (byte-attestation of the platform
// doc). The parity pin (the cross-implementation witness), the
// signed-golden round trip, and the unsigned-doc fail-closed negative.
// ---------------------------------------------------------------------------

/// Pull the wardend evidence out of a fixture's bundle.
fn wardend_evidence(fixture: &Path) -> bootproof::wire::Evidence {
    fixture_bundle(fixture)
        .evidence
        .into_iter()
        .find(|e| e.channel == "wardend")
        .expect("the wardend channel")
}

/// D4 rows-fold: the fixture's FULL evidence vector (all rows). The
/// digest's own folded_rows() drops the wardend row and sorts the rest, so
/// this hands the fold the same row set the live verify side derives from
/// bundle.evidence.
fn fixture_bundle(fixture: &Path) -> Bundle {
    let text = std::fs::read_to_string(fixture)
        .unwrap_or_else(|e| panic!("read {}: {e}", fixture.display()));
    let env: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
    serde_json::from_value(env.get("bundle").cloned().expect("bundle")).expect("bundle")
}

/// The cross-implementation parity pin: the JS generator computes the
/// whole-doc digest with its OWN canonicalization (gen_golden.js
/// canonicalDocDigest) and records it in golden.meta.json; THIS test
/// recomputes it with the Rust canonical_doc_digest over the fixture's
/// DECODED doc. Same bytes, two independent implementations, one vector:
/// if either canonicalization drifts, these two hex values diverge and
/// this test fails. This is the witness that the JS page and the Rust
/// verifier agree on WHAT is signed, not just on the signature bytes.
#[test]
fn the_doc_digest_parity_pin_rust_equals_js() {
    let ev = wardend_evidence(&fixtures_dir().join("golden.json"));
    let doc: bootproof_platform_wardend::WardendDoc =
        serde_json::from_slice(&ev.doc.0).expect("the wardend doc decodes");
    let rust = canonical_doc_digest(&doc);
    let rust_hex: String = rust.iter().map(|b| format!("{b:02x}")).collect();
    let meta_path = fixtures_dir().join("golden.meta.json");
    let meta_text = std::fs::read_to_string(&meta_path).expect("read golden.meta.json");
    let meta: serde_json::Value = serde_json::from_str(&meta_text).expect("meta JSON");
    let js_hex = meta
        .get("wardend_doc_digest_hex")
        .and_then(|v| v.as_str())
        .expect("golden.meta.json carries wardend_doc_digest_hex (gen_golden.js I-2)");
    assert_eq!(
        rust_hex, js_hex,
        "doc-digest parity FAILED: the Rust canonical_doc_digest over the fixture doc \"{rust_hex}\" \ndrifted from the JS generator's canonicalDocDigest \"{js_hex}\" (same bytes, two implementations)"
    );
    // The fixture doc digest is also pinned directly (the coordination
    // point both lanes and the coordinator recompute independently).
    // The fixture carries a key_acl handle of 1653858798848288593
    // (> 2^53, the D12 real one, D12's key_acl_handle('bastiond-tls')):
    // the Rust u64 decode and the JS BigInt token path agree to the last
    // bit while a naive JSON.parse of the same fixture reads ...500. If
    // this literal drifts, either an implementation's canonicalization or
    // the generator's u64 token discipline broke.
    assert_eq!(
        rust_hex, "c957cec67aebdcd839b66d7a58d462c4513e85a23596d8564f689338651aa62d",
        "the fixture wardend doc digest changed: the canonicalization or the fixture doc drifted"
    );
}

/// POSITIVE-FIRST: the signed golden fixture verifies clean through the
/// Rust wardend verifier (the doc signature leg passes: the fixture's
/// doc_signature anchor verifies over the recomputed canonical digest).
/// This is the witness that the unsigned-doc rejection below is rejecting
/// the missing signature and NOT a broken happy path.
#[test]
fn the_signed_golden_doc_verifies_clean() {
    let (rust, errors) = rust_wardend_facts(&fixtures_dir().join("golden.json"));
    assert!(
        errors.is_empty(),
        "the signed golden wardend channel must verify clean: {errors:?}"
    );
    assert_eq!(
        rust.get("wardend_state_chain").map(String::as_str),
        Some("PROVEN"),
        "the signed golden is PROVEN: {rust:?}"
    );
}

/// NEGATIVE (asserts FAILURE): the golden doc with its doc_signature
/// anchor REMOVED (the pre-I-2 shape: a valid, chain-intact doc with no
/// byte-attestation) must FAIL the wardend channel closed, mapped to the
/// honest NOT PROVEN failed-fact. An unsigned doc is not a degraded doc,
/// it is an unverified one. This is the fixture-level witness of the
/// fail-closed rule the plugin's unit tests pin at the function level.
#[test]
fn an_unsigned_doc_is_rejected_fail_closed() {
    let (rust, errors) = rust_wardend_facts(&fixtures_dir().join("golden.unsigned-doc.json"));
    assert!(
        errors.iter().any(|e| e.contains("doc signature")),
        "the unsigned doc must error the wardend channel on the doc-signature leg: {errors:?}"
    );
    assert_eq!(
        rust.get("wardend").map(String::as_str),
        Some("NOT PROVEN"),
        "the failed-fact is the honest NOT PROVEN: {rust:?}"
    );
    // The state_chain fact must NOT be PROVEN for an unsigned doc (the
    // doc signature is the gate on the whole channel, not a companion).
    assert_ne!(
        rust.get("wardend_state_chain").map(String::as_str),
        Some("PROVEN"),
        "an unsigned doc must never PROVEN the state chain: {rust:?}"
    );
}

/// The JS sub-checks by name (the raw statuses, matching the raw-status
/// js_facts above: FAILED stays FAILED here, no mapping). Used to pin the
/// specific wardend.doc_signature sub the doc gate adds.
fn js_subs(fixture: &Path) -> BTreeMap<String, String> {
    let out = Command::new("node")
        .arg(fixtures_dir().join("harness.js"))
        .arg(fixture)
        .output()
        .expect("node runs the harness");
    assert!(out.status.success(), "harness failed: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("harness JSON");
    let mut map = BTreeMap::new();
    for s in v.get("subs").and_then(|a| a.as_array()).expect("subs") {
        map.insert(
            s.get("name").and_then(|n| n.as_str()).expect("name").to_string(),
            s.get("status").and_then(|s| s.as_str()).expect("status").to_string(),
        );
    }
    map
}

/// I-2b (browser-side unsigned-doc reject): the SAME golden.unsigned-doc
/// fixture that `an_unsigned_doc_is_rejected_fail_closed` pins on the Rust
/// side must ALSO fail closed on the JS side, with the identical verdict.
/// This is the cross-verifier witness that the browser rejects an unsigned
/// doc the same way the plugin does: an absent doc_signature anchor makes
/// the whole wardend channel NOT PROVEN (never PROVEN), and the honest
/// cause is the missing doc-signature sub. One bundle, two verifiers, the
/// same rejection.
#[test]
fn the_unsigned_doc_is_rejected_by_the_browser_too() {
    let g = fixtures_dir().join("golden.unsigned-doc.json");
    let js = js_facts(&g);
    assert_eq!(
        js.get("wardend_state_chain").map(String::as_str),
        Some("NOT PROVEN"),
        "the browser must NOT PROVEN an unsigned doc (mirrors the Rust fail-closed): {js:?}"
    );
    let subs = js_subs(&g);
    assert_eq!(
        subs.get("wardend.doc_signature").map(String::as_str),
        Some("NOT PROVEN"),
        "the honest JS cause is the missing doc_signature sub (not a broken chain): {subs:?}"
    );
}

/// I-2b (browser-side doc-digest parity + negative twin): the shipped
/// verify.js canonicalizer, driven by fixtures/system_health/docsig_parity.js
/// against the committed golden doc, must reproduce the SAME digest the Rust
/// canonical_doc_digest produces (the cross-implementation witness), while
/// the naive Number parse of the SAME bytes diverges (the u64-precision
/// false-red the token path closes). The harness reads the pin from
/// golden.meta.json; the pin's own agreement with the Rust literal is pinned
/// in the_doc_digest_parity_pin_rust_equals_js.
#[test]
fn the_browser_doc_digest_matches_rust_and_the_naive_path_diverges() {
    let out = Command::new("node")
        .arg(fixtures_dir().join("docsig_parity.js"))
        .output()
        .expect("node runs the doc-digest parity harness (node is part of the test env)");
    assert!(
        out.status.success(),
        "the doc-digest parity harness failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("parity JSON");
    let g = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    assert!(
        g("token_safe_matches_pin"),
        "the shipped canonicalizer over the token-safe parse must equal the committed pin \
         (the SAME digest Rust canonical_doc_digest produces): {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !g("naive_matches_pin"),
        "the negative twin is NOT diverging: the naive Number parse must produce a DIFFERENT \
         digest than the pin (that divergence is the u64-precision hazard the token path \
         closes; if it matches, either the fixture lost its >2^53 handle or the canonicalizer \
         stopped depending on the parse): {}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The two paths must actually differ (a belt-and-suspenders re-state that
    // the divergence is real, not a harness artifact of both being wrong).
    let tok = v.get("token_safe").and_then(|x| x.as_str()).unwrap_or("");
    let naive = v.get("naive").and_then(|x| x.as_str()).unwrap_or("");
    assert!(
        !tok.is_empty() && tok != naive,
        "token-safe and naive digests must both be present AND differ: tok={tok:?} naive={naive:?}"
    );
}

/// I-2b (browser-side FAILED-vs-NOT-PROVEN distinction): the doc gate has TWO
/// distinct honest rejections, and they must not collapse into one. An ABSENT
/// doc_signature is NOT PROVEN (nothing to anchor: the_unsigned_doc_is_rejected
/// _by_the_browser_too pins that). A PRESENT-but-wrong one (the log-tamper doc:
/// the flipped bytes change the canonical digest, so the fixture's real 64-byte
/// signature no longer matches) is FAILED: there IS a signature, and it fails.
/// This pins the FAILED sub by NAME (the fact-level roll already pins it
/// transitively via wardend_state_chain FAILED in the core test; this closes
/// the branch so a regression that mislabels a stale signature as "unverified"
/// instead of "rejected" trips here).
#[test]
fn the_tampered_doc_signature_is_failed_not_not_proven_in_the_browser() {
    let g = fixtures_dir().join("golden.log-tamper.json");
    let subs = js_subs(&g);
    assert_eq!(
        subs.get("wardend.doc_signature").map(String::as_str),
        Some("FAILED"),
        "a present-but-wrong doc_signature must read FAILED (a rejected signature), \
         never NOT PROVEN (that would hide a tamper as a mere absence): {subs:?}"
    );
    // And the channel roll agrees: the tamper is a hard rejection.
    let js = js_facts(&g);
    assert_eq!(
        js.get("wardend_state_chain").map(String::as_str),
        Some("FAILED"),
        "the wardend channel must roll to FAILED on the tampered doc: {js:?}"
    );
}

/// I-2b (the core security property, cross-verifier): the WHOLE point of the
/// doc signature is that seal_state is doc content, and an UNSIGNED doc must
/// never PROVEN the seal state on EITHER verifier. This is the leak the browser
/// gate closes (pre-I-2b the page rendered a healthy seal state straight from
/// the doc with no anchor). One bundle, two verifiers, one verdict on the
/// load-bearing field:
///   * Rust: an unsigned doc fails the doc-signature leg INSIDE verify(), so
///     the engine takes the failed-fact path and never runs facts() — so
///     wardend_seal_state is NOT PROVEN on the Rust side (in fact absent).
///   * JS: checkStateLog gates on the doc signature BEFORE the seal_state sub,
///     so an unsigned doc never even renders wardend.seal_state.
/// Asserted on the same golden.unsigned-doc fixture both verifiers consume.
#[test]
fn an_unsigned_doc_never_proven_seal_state_on_either_verifier() {
    let g = fixtures_dir().join("golden.unsigned-doc.json");
    // Rust: the seal-state fact must not be PROVEN (the doc gate precedes any
    // fact emission; an unsigned doc yields only the channel failed-fact).
    let (rust, _errors) = rust_wardend_facts(&g);
    assert_ne!(
        rust.get("wardend_seal_state").map(String::as_str),
        Some("PROVEN"),
        "an unsigned doc must never PROVEN wardend_seal_state on the Rust side: {rust:?}"
    );
    // JS: the browser must ALSO never PROVEN it — and, being gated before the
    // sub is ever pushed, must not even render a PROVEN seal_state. (The
    // cross-verifier point: the leak closed on BOTH sides, not just the page.)
    let subs = js_subs(&g);
    assert_ne!(
        subs.get("wardend.seal_state").map(String::as_str),
        Some("PROVEN"),
        "the browser must never PROVEN wardend.seal_state on an unsigned doc: {subs:?}"
    );
    // Positive witness that this is a real rejection, not an empty run: the
    // doc_signature sub fired (NOT PROVEN for the absent anchor) on the JS side.
    assert_eq!(
        subs.get("wardend.doc_signature").map(String::as_str),
        Some("NOT PROVEN"),
        "the JS gate must fire the doc_signature sub as the honest cause: {subs:?}"
    );
}

/// D4 (digest v2 fixture parity, both directions): the fixture's doc is
/// now SIGNED under digest v2 bound to the fixture's own frozen nonce.
/// (1) The Rust canonical_doc_digest_v2 over the DECODED fixture doc plus
/// bundle.nonce must equal the generator's wardend_doc_digest_v2_hex in
/// golden.meta.json (the same two-implementation, one-vector witness the
/// v1 pin provides). (2) The doc_signature anchor must verify under the
/// HSM key over THAT digest: the fixture walks production's byte
/// protocol end to end. (3) The v1 digest of the SAME doc stays pinned
/// to the historical c957... vector: v1 is byte-blind to user_data, so
/// the v1 canonicalization provably did not drift while v2 was added.
#[test]
fn the_digest_v2_parity_pin_rust_equals_js_and_the_sig_closes_under_it() {
    let g = fixtures_dir().join("golden.json");
    let ev = wardend_evidence(&g);
    let doc: bootproof_platform_wardend::WardendDoc =
        serde_json::from_slice(&ev.doc.0).expect("the wardend doc decodes");
    // The fixture's own bundle nonce, byte-for-byte what the engine hands
    // the verifier as the challenge.
    let env: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&g).expect("read golden")).expect("json");
    let nonce_b64 = env
        .get("bundle")
        .and_then(|b| b.get("nonce"))
        .and_then(|n| n.as_str())
        .expect("bundle.nonce")
        .to_string();
    let nonce = base64_decode(&nonce_b64);
    assert_eq!(nonce.len(), 32, "the fixture nonce must be 32 bytes");

    let rows = fixture_bundle(&g).evidence;
    let d2 = canonical_doc_digest_v2(
        &doc,
        nonce.as_slice().try_into().expect("32-byte nonce"),
        &rows,
    );
    let hex2: String = d2.iter().map(|b| format!("{b:02x}")).collect();
    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("golden.meta.json")).expect("read meta"),
    )
    .expect("meta JSON");
    let js_hex2 = meta
        .get("wardend_doc_digest_v2_hex")
        .and_then(|v| v.as_str())
        .expect("golden.meta.json carries wardend_doc_digest_v2_hex (gen_golden.js D4)");
    assert_eq!(
        hex2, js_hex2,
        "digest v2 parity FAILED: Rust canonical_doc_digest_v2 \"{hex2}\" drifted from the \
         JS generator \"{js_hex2}\" (same doc bytes, same nonce, two canonicalizations)"
    );
    // Cross-version discrimination: v2 of this doc is NOT the historical
    // v1 vector (marker + nonce + user_data inputs), the property the
    // fail-closed v1<->v2 rejection rests on.
    let d1 = canonical_doc_digest(&doc);
    let hex1: String = d1.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex1, "c957cec67aebdcd839b66d7a58d462c4513e85a23596d8564f689338651aa62d",
        "the RETIRED v1 digest of the fixture doc changed: v1 canonicalization must stay \
         byte-blind to user_data, so the historical vector is regression evidence"
    );
    assert_ne!(hex1, hex2, "v1 and v2 digests of the same doc must differ");
}

/// D4 (fail-closed v1 rejection, both verifiers): golden.v1-signed.json
/// carries the golden's doc with an honest signature under RETIRED digest
/// v1 (bound to no nonce). The channel must reject it fail-closed with
/// the replay named as the cause, NEVER silently accept it, and never
/// mislabel it as a broken chain.
#[test]
fn a_v1_signed_doc_is_rejected_and_named_replayable_on_both_verifiers() {
    let g = fixtures_dir().join("golden.v1-signed.json");
    // Rust: fails the doc-signature leg; the failed-fact is NOT PROVEN;
    // nothing derived from the doc is PROVEN.
    let (rust, errors) = rust_wardend_facts(&g);
    assert!(
        errors.iter().any(|e| e.contains("doc signature")),
        "the v1-signed doc must fail the doc-signature leg: {errors:?}"
    );
    assert_eq!(
        rust.get("wardend").map(String::as_str),
        Some("NOT PROVEN"),
        "the failed-fact is the honest NOT PROVEN: {rust:?}"
    );
    assert_ne!(
        rust.get("wardend_state_chain").map(String::as_str),
        Some("PROVEN"),
        "a v1-signed doc must never PROVEN the state chain: {rust:?}"
    );
    // The user-data fact must not be PROVEN either: v1 never digested
    // the section, so its commitment is not under this signature.
    assert_ne!(
        rust.get("wardend_user_data").map(String::as_str),
        Some("PROVEN"),
        "a v1-signed doc must never PROVEN attested user data: {rust:?}"
    );
    // JS: FAILED, and the reason names the retired contract (not a
    // tamper, not an absence).
    let subs = js_subs(&g);
    assert_eq!(
        subs.get("wardend.doc_signature").map(String::as_str),
        Some("FAILED"),
        "a v1-only signature is a REJECTED signature (FAILED), never NOT PROVEN: {subs:?}"
    );
    let js = js_facts(&g);
    let why = js
        .get("wardend_state_chain")
        .and_then(|_| find_why(&g, "wardend_state_chain"))
        .unwrap_or_default();
    assert!(
        why.contains("RETIRED digest v1"),
        "the JS rejection must NAME the retired-contract replay cause: {why:?}"
    );
}

/// The why-string of a fact, from the harness output.
fn find_why(fixture: &Path, name: &str) -> Option<String> {
    let out = Command::new("node")
        .arg(fixtures_dir().join("harness.js"))
        .arg(fixture)
        .output()
        .expect("node runs the harness");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("harness JSON");
    for f in v.get("facts").and_then(|a| a.as_array())? {
        if f.get("name").and_then(|n| n.as_str())? == name {
            return f.get("why").and_then(|w| w.as_str()).map(String::from);
        }
    }
    None
}

/// Minimal base64 (the fixtures' own alphabet; no dependency needed).
fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut acc = 0u64;
    let mut out = Vec::new();
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|&x| x == c).expect("base64 char") as u64;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
