// The two-verifiers-agree gate (the contract's cross-verifier acceptance
// test, core scope): ONE golden fixture envelope, verified by BOTH
// verifiers, with the fact verdicts asserted identical name-for-name:
//
//   * Rust: engine::verify_bundle with the core registry (snp + tpm2).
//   * JS:   the service worker verify.js, driven headless by
//     fixtures/system_health/harness.js (node + WebCrypto), printing the
//     same fact verdicts as JSON.
//
// Scope: the core test covers the snp + tpm2 channels (the core engine
// must never depend on a platform crate, so the wardend channel errors as
// "no verifier" HERE; its agreement lives in
// crates/bootproof-platform-wardend/tests/).
//
// The frozen verdict vocabulary mapping (documented in AGENTS.md):
//   * A rejected snp channel: Rust emits the memory_encryption NOT PROVEN
//     failed-fact + a channel error; JS emits memory_encryption FAILED.
//     Mapping: NOT PROVEN <-> FAILED (the Rust wire has no Failed status).
//   * A rejected tpm2 channel (fold mismatch): Rust emits NO tpm facts at
//     all + a loud channel error (Tpm2Verifier has no failed_fact: every
//     tpm fact comes from a fully verified quote or nothing); JS rolls
//     tpm_quote to FAILED. Mapping: absent-fact + error <-> FAILED fact.
// The golden asserts EXACT status equality (everything PROVEN/DEGRADED
// there); the tamper fixtures assert the mapped rejection on both sides
// plus the shared REJECTION itself (the security property: a tamper never
// verifies).
//
// Regenerate the fixtures with: node fixtures/system_health/gen_golden.js
use bootproof::engine::{verify_bundle, VerifierRegistry, VerifyPolicy};
use bootproof::verify::snp::SnpVerifier;
use bootproof::verify::tpm2::Tpm2Verifier;
use bootproof::wire::{Bundle, Status};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/system_health")
}

/// The typed-schema gate (the fixture-vs-schema drift killer): decode a
/// fixture through the REAL `system_health::schema::Envelope` type, not a
/// `serde_json::Value`. Value-level consumption was the hole that let the
/// golden drift from the schema (the identity block omitted a
/// schema-declared field and nothing typed ever saw it). Every fixture
/// must be a valid typed `Envelope` BEFORE the verdict crosswalk runs.
///
/// `system_health` is the feature that owns the schema; the gate is gated
/// with it (the acceptance gate runs `--features system-health`). On top of
/// the structural decode, the golden's identity is asserted to carry the
/// `leaf_pem_present` key EXPLICITLY: the schema leniently defaults that
/// field (absent == honest false), so a bare `from_str` would NOT catch an
/// omission, and this Value-level presence assert is what pins the exact
/// drift that started this.
#[cfg(feature = "system-health")]
fn typed_envelope(fixture: &Path) -> bootproof::system_health::schema::Envelope {
    let text = std::fs::read_to_string(fixture)
        .unwrap_or_else(|e| panic!("read {}: {e}", fixture.display()));
    let env: bootproof::system_health::schema::Envelope =
        serde_json::from_str(&text).unwrap_or_else(|e| {
            panic!("{} is not a valid schema::Envelope: {e}", fixture.display())
        });
    env
}

/// Assert the schema-declared `identity.leaf_pem_present` key is present
/// EXPLICITLY in a fixture's JSON (the value is the dual-location server
/// claim; the golden publishes no leaf so it must be `false`). The typed
/// `#[serde(default)]` cannot catch an omission; this does.
fn assert_identity_leaf_claim_explicit(fixture: &Path, expected: bool) {
    let text = std::fs::read_to_string(fixture).expect("fixture readable");
    let v: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
    let id = v.get("identity").expect("identity section");
    let claim = id.get("leaf_pem_present");
    assert_eq!(
        claim.and_then(|x| x.as_bool()),
        Some(expected),
        "{}: identity.leaf_pem_present must be the explicit {expected}",
        fixture.display()
    );
}

/// The Rust side: verify a fixture bundle with the core registry. Returns
/// (fact name -> normalized status, the errors). The wardend channel is
/// intentionally NOT registered here (the core never depends on a platform
/// crate): its "no verifier" error is filtered from the pass checks by the
/// callers that expect it.
fn rust_facts(fixture: &Path) -> (BTreeMap<String, String>, Vec<String>) {
    // The typed-schema gate runs FIRST: a fixture that is not a valid
    // schema::Envelope must fail here, before any verdict is derived.
    #[cfg(feature = "system-health")]
    let _ = typed_envelope(fixture);
    assert_identity_leaf_claim_explicit(fixture, false);
    let text = std::fs::read_to_string(fixture)
        .unwrap_or_else(|e| panic!("read {}: {e}", fixture.display()));
    let env: serde_json::Value = serde_json::from_str(&text).expect("fixture is JSON");
    let bundle: Bundle =
        serde_json::from_value(env.get("bundle").expect("fixture carries a bundle").clone())
            .expect("the bundle deserializes against the frozen wire contract");
    let mut reg = VerifierRegistry::new();
    reg.register(Box::new(SnpVerifier));
    reg.register(Box::new(Tpm2Verifier));
    let mut vf = verify_bundle(&bundle, &VerifyPolicy::default_policy(), &reg);
    // The wardend channel is out of scope for the core registry: its
    // "no verifier for channel wardend" error is not a divergence signal
    // here (the plugin test owns that channel).
    vf.errors.retain(|e| !e.contains("wardend"));
    let mut map = BTreeMap::new();
    for f in &vf.facts {
        map.insert(f.name.clone(), normalize(f.status).to_string());
    }
    (map, vf.errors)
}

/// The JS side: run the harness (the REAL verify.js in a vm) and parse its
/// fact verdicts. Panics (fail the test) when node is missing or the
/// harness fails: node is part of the documented test environment, and a
/// silently skipped agreement test is no gate.
fn js_facts(fixture: &Path) -> BTreeMap<String, String> {
    let fixtures = fixtures_dir();
    let out = Command::new("node")
        .arg(fixtures.join("harness.js"))
        .arg(fixture)
        .output()
        .expect("node runs the harness (node is part of the test environment)");
    assert!(
        out.status.success(),
        "harness failed on {}: {}",
        fixture.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("the harness prints valid JSON");
    let mut map = BTreeMap::new();
    for f in v.get("facts").and_then(|f| f.as_array()).expect("facts array") {
        let name = f.get("name").and_then(|n| n.as_str()).expect("fact name").to_string();
        let status = f.get("status").and_then(|s| s.as_str()).expect("fact status").to_string();
        map.insert(name, normalize_str(&status));
    }
    map
}

/// JS subs by name (the per-check verdicts the Rust facts-level map
/// mirrors: slot_link <-> tpm.slot_link, sign_key <-> tpm.sign_key, ...).
fn js_subs(fixture: &Path) -> BTreeMap<String, String> {
    let fixtures = fixtures_dir();
    let out = Command::new("node")
        .arg(fixtures.join("harness.js"))
        .arg(fixture)
        .output()
        .expect("node runs the harness");
    assert!(out.status.success(), "harness failed: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("harness JSON");
    let mut map = BTreeMap::new();
    for s in v.get("subs").and_then(|f| f.as_array()).expect("subs array") {
        let name = s.get("name").and_then(|n| n.as_str()).expect("sub name").to_string();
        let status = s.get("status").and_then(|s| s.as_str()).expect("sub status").to_string();
        map.insert(name, normalize_str(&status));
    }
    map
}

fn normalize(s: Status) -> &'static str {
    match s {
        Status::Proven => "PROVEN",
        Status::Reproducible => "REPRODUCIBLE",
        Status::Degraded => "DEGRADED",
        Status::NotProven => "NOT PROVEN",
    }
}
fn normalize_str(s: &str) -> String {
    match s {
        // The JS vocabulary (identical wire strings except FAILED, which
        // has no Rust Status: the documented rejection-side divergence).
        "FAILED" => "FAILED (mapped)".to_string(),
        other => other.to_string(),
    }
}

fn fixture(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

/// The golden envelope: exact status equality, fact-for-fact, between the
/// Rust engine and the service worker, on every shared fact name. This is
/// the "one bundle, two verifiers, one verdict" gate.
#[test]
fn golden_two_verifiers_agree() {
    let g = fixture("golden.json");
    let (rust, errors) = rust_facts(&g);
    assert!(errors.is_empty(), "the golden must verify without errors: {errors:?}");
    let js = js_facts(&g);
    let js_subs = js_subs(&g);

    // 1. The shared top-level facts: identical names AND identical
    //    statuses (the golden has no rejections, so the mapping never
    //    fires: strict equality holds). pcr_state is a FACT in Rust and
    //    a SUB in the JS roll: it rides the crosswalk table in step 2.
    let shared = ["memory_encryption", "tpm_quote"];
    for name in shared {
        let r = rust.get(name).unwrap_or_else(|| panic!("rust emitted no {name} fact: {rust:?}"));
        let j = js.get(name).unwrap_or_else(|| panic!("js emitted no {name} fact: {js:?}"));
        assert_eq!(r, j, "golden: {name} diverged between the two verifiers");
    }

    // 2. The fact-vs-sub crosswalk (the verdict algebra): the Rust
    //    per-check facts must equal the JS sub-check verdicts they
    //    mirror. The JS tpm_quote fact is the worst-of roll of its subs;
    //    the Rust facts are the individual checks, so the fact-level
    //    equality above plus these pairs pins BOTH layers.
    let pairs = [
        ("slot_link", "tpm.slot_link"),
        ("sign_key", "tpm.sign_key"),
        ("ek_cert", "tpm.ek_cert"),
        ("pcr_state", "tpm.pcr_state"),
        // AMI-2: the snp identity rows are Rust FACTS and JS SUBs over
        // the same bundle -- the same fact-vs-sub crosswalk algebra the
        // tpm rows use, now covering the hardware-identity pair
        // (browser-side checks, gated on the report signature on both
        // sides).
        ("snp_cpu_identity", "snp.cpu_identity"),
        ("snp_chip_identity", "snp.chip_identity"),
        // The bake-11 fold row: NOT PROVEN on every fixture at BOTH scopes
        // (core: empty candidates by law; browser: equality is theater until
        // #19), so the pair pins exact equality forever, field goldens
        // included (both sides stay NOT PROVEN even when the tail equals the
        // real pin -- attribution is platform/wardenctl scope).
        ("snp_identity_tail", "snp.identity_tail"),
    ];
    for (rfact, jsub) in pairs {
        let r = rust.get(rfact).unwrap_or_else(|| panic!("rust emitted no {rfact} fact"));
        let j = js_subs.get(jsub).unwrap_or_else(|| panic!("js emitted no {jsub} sub"));
        assert_eq!(r, j, "golden: rust {rfact} != js {jsub}");
    }

    // 3. The expected verdicts (regeneration drift trips this too).
    assert_eq!(rust.get("memory_encryption").map(String::as_str), Some("PROVEN"));
    assert_eq!(rust.get("tpm_quote").map(String::as_str), Some("PROVEN"));
    assert_eq!(rust.get("slot_link").map(String::as_str), Some("PROVEN"));
    assert_eq!(rust.get("sign_key").map(String::as_str), Some("PROVEN"));
    assert_eq!(rust.get("ek_cert").map(String::as_str), Some("DEGRADED"));
    // AMI-2 positive-first on the live Milan-generation report: the CPU
    // identity PROVENs (the model number is real) and the chip identity
    // says NOT PROVEN through the zero-rule (the firmware reports 64
    // zero bytes). Both statuses agree across the verifiers through the
    // crosswalk above; these literals pin WHICH side of the zero-rule
    // the golden lands on, so a generator change cannot quietly flip it.
    assert_eq!(rust.get("snp_cpu_identity").map(String::as_str), Some("PROVEN"));
    assert_eq!(rust.get("snp_chip_identity").map(String::as_str), Some("NOT PROVEN"));
    // The founding Unattributed datum at e2e scope: the live report's tail
    // (ac0e6a94…74a18, folded by the live host pre-design) matches nothing
    // the core can derive -- the row is NOT PROVEN through the UNATTRIBUTED
    // arm (never FAILED: content never fails, the signature does).
    assert_eq!(rust.get("snp_identity_tail").map(String::as_str), Some("NOT PROVEN"));
    // The JS-only fact the core does not own here (wardend): must be
    // PROVEN on the JS side of the golden (the plugin test proves the
    // Rust side; the envelope-level fact must not diverge once the
    // plugin registry is complete).
    assert_eq!(js.get("wardend_state_chain").map(String::as_str), Some("PROVEN"));
}

/// Tamper 1 (snp-tamper): one report_data byte flipped. BOTH verifiers
/// must REJECT both hardware facts, through the documented mapping:
///   * snp: Rust memory_encryption NOT PROVEN (failed-fact) + a snp
///     channel error; JS memory_encryption FAILED.
///   * tpm fold: the flipped bytes are fold input (PCR22 hashes the snp
///     doc), so Rust ERRORS the whole tpm2 channel and emits NO tpm facts
///     (the honest all-or-nothing tpm contract); JS rolls tpm_quote to
///     FAILED. Same rejection, documented placement divergence.
#[test]
fn snp_tamper_rejected_by_both() {
    let g = fixture("golden.snp-tamper.json");
    let (rust, errors) = rust_facts(&g);
    assert!(
        errors.iter().any(|e| e.starts_with("snp:")),
        "rust must error the tampered snp channel: {errors:?}"
    );
    assert_eq!(
        rust.get("memory_encryption").map(String::as_str),
        Some("NOT PROVEN"),
        "rust memory_encryption must be the honest rejection fact"
    );
    // The fold input changed: Rust fails the ENTIRE tpm2 channel loudly
    // (an error, and no tpm facts at all).
    assert!(
        errors.iter().any(|e| e.starts_with("tpm2:")),
        "rust must error the tpm2 channel whose fold broke: {errors:?}"
    );
    assert!(
        !rust.contains_key("tpm_quote") && !rust.contains_key("pcr_state"),
        "a rejected tpm2 channel emits NO tpm facts (all-or-nothing): {rust:?}"
    );

    // JS: the same two rejections, in the FAILED vocabulary.
    let js = js_facts(&g);
    assert_eq!(
        js.get("memory_encryption").map(String::as_str),
        Some("FAILED (mapped)"),
        "js memory_encryption must be FAILED (maps to rust NOT PROVEN)"
    );
    assert_eq!(
        js.get("tpm_quote").map(String::as_str),
        Some("FAILED (mapped)"),
        "js tpm_quote must be FAILED: the slot fold broke with the doc bytes"
    );
}

/// Tamper 2 (missing-snp): the snp channel dropped entirely. EXACT
/// status agreement: Rust's required-absent fact and the JS's honest
/// NOT_PROVEN both spell NOT PROVEN (name AND status, no mapping needed).
/// The fold breaks on both sides too (the dropped doc changed the other-
/// docs concatenation): Rust errors the tpm2 channel with no tpm facts,
/// JS rolls tpm_quote to FAILED.
#[test]
fn missing_snp_exact_not_proven_agreement() {
    let g = fixture("golden.missing-snp.json");
    // The typed-schema gate: this test decodes inline (custom policy), so
    // the gate + the explicit identity claim are asserted on its own path
    // too: every fixture passes through the typed schema.
    #[cfg(feature = "system-health")]
    let _ = typed_envelope(&g);
    assert_identity_leaf_claim_explicit(&g, false);
    // Register the snp verifier as a REQUIRED channel: the honest
    // required-absent fact is the engine behavior under test.
    let text = std::fs::read_to_string(&g).expect("fixture readable");
    let env: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
    let bundle: Bundle = serde_json::from_value(env.get("bundle").cloned().expect("bundle"))
        .expect("bundle deserializes");
    let mut reg = VerifierRegistry::new();
    reg.register(Box::new(SnpVerifier));
    reg.register(Box::new(Tpm2Verifier));
    let policy = VerifyPolicy {
        required_vmpl: 0,
        required_channels: vec!["snp".into(), "tpm2".into()],
    };
    let vf = verify_bundle(&bundle, &policy, &reg);
    let me = vf
        .facts
        .iter()
        .find(|f| f.name == "memory_encryption")
        .expect("the required-absent fact is reported, never silently dropped");
    assert_eq!(me.status, Status::NotProven, "required-absent snp is NOT PROVEN");
    // AMI-2 absence silence: an absent report has NO bytes to display, so
    // neither verifier emits an identity row (the required_absent_facts
    // default deliberately stays silent -- absence is honest silence, not
    // a row saying NOT PROVEN; tampering is the present-row-not-proven
    // state the chip-tamper test pins). This pair keeps the two states
    // distinguishable in the contract, tested.
    assert!(
        !vf.facts.iter().any(|f| f.name == "snp_cpu_identity" || f.name == "snp_chip_identity" || f.name == "snp_identity_tail"),
        "an absent snp channel emits NO identity rows: {vf:?}"
    );

    let js = js_facts(&g);
    assert_eq!(
        js.get("memory_encryption").map(String::as_str),
        Some("NOT PROVEN"),
        "exact agreement: both verifiers spell the dropped channel NOT PROVEN"
    );
    let js_subs = js_subs(&g);
    assert!(
        !js_subs.contains_key("snp.cpu_identity") && !js_subs.contains_key("snp.chip_identity")
            && !js_subs.contains_key("snp.identity_tail"),
        "the JS side stays silent on the identity rows for an absent channel (the mirrored exception): {js_subs:?}"
    );
    // The fold broke (the dropped doc is missing from the fold input):
    // Rust errors the whole tpm2 channel with no tpm facts; JS rolls
    // tpm_quote to FAILED. Same rejection, documented placement split.
    assert!(
        vf.errors.iter().any(|e| e.starts_with("tpm2:")),
        "rust must error the tpm2 fold over the dropped docs: {:?}",
        vf.errors
    );
    assert!(
        !vf.facts.iter().any(|f| f.name == "tpm_quote"),
        "a rejected tpm2 channel emits no tpm facts"
    );
    assert_eq!(js.get("tpm_quote").map(String::as_str), Some("FAILED (mapped)"));
}

/// Tamper (chip-tamper, AMI-2): one CHIP_ID byte flipped @0x1A0, inside
/// the VLEK-signed prefix but OUTSIDE report_data -- the nonce binding
/// stays green and ONLY the report signature dies. This is the identity
/// rows' failure leg and the failed_facts() override's whole point:
///   * Rust: THREE NOT PROVEN facts (memory_encryption + snp_cpu_identity
///     + snp_chip_identity) from the ONE failure -- the plural contract.
///     The CPU row that PROVENs on the golden must flip here: an attacker
///     rewriting the chip serial also invalidates the model row, because
///     the bytes it reads are no longer attested.
///   * JS: memory_encryption FAILED; both identity SUBs NOT PROVEN with
///     the unattested-bytes reason (the exact-status vocabulary the
///     engine's own failed_facts/required_absent path uses on the Rust
///     side -- a JS FAILED would overclaim: the rows are unattested, not
///     proven-false).
/// The tpm fold breaks on both sides like every snp-doc tamper.
#[test]
fn chip_tamper_not_provens_the_identity_rows_on_both() {
    let g = fixture("golden.chip-tamper.json");
    let (rust, errors) = rust_facts(&g);
    assert!(
        errors.iter().any(|e| e.starts_with("snp:")),
        "rust must error the tampered snp channel: {errors:?}"
    );
    for name in ["memory_encryption", "snp_cpu_identity", "snp_chip_identity", "snp_identity_tail"] {
        assert_eq!(
            rust.get(name).map(String::as_str),
            Some("NOT PROVEN"),
            "one report-signature failure NOT PROVENS every fact the snp channel owns ({name})"
        );
    }
    assert!(
        errors.iter().any(|e| e.starts_with("tpm2:")),
        "the flipped doc is fold input: the tpm2 channel must error too: {errors:?}"
    );

    let js = js_facts(&g);
    let js_subs = js_subs(&g);
    assert_eq!(js.get("memory_encryption").map(String::as_str), Some("FAILED (mapped)"));
    for jsub in ["snp.cpu_identity", "snp.chip_identity", "snp.identity_tail"] {
        assert_eq!(
            js_subs.get(jsub).map(String::as_str),
            Some("NOT PROVEN"),
            "the JS identity row {jsub} must be NOT PROVEN on a broken signature, not FAILED: {js_subs:?}"
        );
    }
    // Positive-first control on the SAME run: the tamper left the nonce
    // binding green (0x1A0 is outside report_data), so the rows' gate --
    // not the binding -- is what failed. If the fixture ever drifts and
    // the binding also breaks, this trips and the test's premise is
    // re-examined rather than silently weakened.
    assert_eq!(
        js_subs.get("snp.nonce_binding").map(String::as_str),
        Some("PROVEN"),
        "chip-tamper must kill ONLY the signature leg: the binding stays green"
    );
    assert_eq!(
        js_subs.get("snp.report_sig").map(String::as_str),
        Some("FAILED (mapped)"),
        "the report signature is the leg that dies"
    );
}

/// Tamper (tail-zero-tamper, bake-11 fold): the identity tail
/// (report_data[32..64]) ZEROED on a report whose firmware signature covers
/// the ORIGINAL non-zero tail. The expected outcome is pinned in the fixture
/// generator (gen_golden.js): the VLEK signature MUST die — tail content
/// never PASSES a broken signature. This is the structural proof of the
/// amended classify law at e2e scope: the zeroed tail would classify
/// NotEnabled on a VERIFIED report, but no report here verifies; the tier is
/// the signature's verdict, never the content's. The documented
/// content-vs-signature divergence class:
///   * Rust: the snp channel errors; failed_facts NOT-PROVENs ALL FOUR
///     facts (memory_encryption + cpu + chip + identity_tail).
///   * JS: memory_encryption FAILED; the identity SUBs NOT PROVEN with the
///     unattested-bytes reason (never FAILED: unattested, not proven-false).
/// Agreement is asserted on the REJECTION, never the tier. (A CLEAN
/// zero-tail NotEnabled golden is unmintable here by law: it needs a
/// firmware-signed zero tail — the field carrier at bake-11 boot-N.)
#[test]
fn tail_zero_tamper_dies_on_the_signature_on_both() {
    let g = fixture("golden.tail-zero-tamper.json");
    let (rust, errors) = rust_facts(&g);
    assert!(
        errors.iter().any(|e| e.starts_with("snp:")),
        "the zeroed tail breaks the VLEK signature: the snp channel must error: {errors:?}"
    );
    for name in ["memory_encryption", "snp_cpu_identity", "snp_chip_identity", "snp_identity_tail"] {
        assert_eq!(
            rust.get(name).map(String::as_str),
            Some("NOT PROVEN"),
            "the ONE signature failure NOT PROVENS all four owned facts ({name}) — \
             the zeroed tail must NOT launder into a clean NotEnabled row"
        );
    }
    // The tail bytes ARE the fold input (the snp doc hashes into PCR22):
    // the tpm2 fold must break loudly too, like every snp-doc tamper.
    assert!(
        errors.iter().any(|e| e.starts_with("tpm2:")),
        "the zeroed tail changed the fold input: the tpm2 channel must error: {errors:?}"
    );

    let js = js_facts(&g);
    let js_subs = js_subs(&g);
    assert_eq!(js.get("memory_encryption").map(String::as_str), Some("FAILED (mapped)"));
    for jsub in ["snp.cpu_identity", "snp.chip_identity", "snp.identity_tail"] {
        assert_eq!(
            js_subs.get(jsub).map(String::as_str),
            Some("NOT PROVEN"),
            "the JS row {jsub} is NOT PROVEN (unattested), never FAILED, on the broken signature: {js_subs:?}"
        );
    }
    // The tail row's REASON must carry the signature-gate wording, NOT the
    // NotEnabled wording: the tail is zero, but the honest reading is
    // "bytes unattested", not "fold not enabled" (which would imply the
    // zeros were attested).
    let why = harness_why(&g, "snp.identity_tail");
    assert!(
        why.contains("identity bytes unattested"),
        "the tail-zero tamper row must name the signature gate, not the zero-rule: {why}"
    );
    // And the browser's fact-level rejection on the fold:
    assert_eq!(js.get("tpm_quote").map(String::as_str), Some("FAILED (mapped)"));
}

/// The harness why-text for one sub (the verdict maps drop reasons; the
/// tamper tests need the reason text to pin WHAT the row says, not just
/// its status).
fn harness_why(fixture: &Path, sub_name: &str) -> String {
    let fixtures = fixtures_dir();
    let out = Command::new("node")
        .arg(fixtures.join("harness.js"))
        .arg(fixture)
        .output()
        .expect("node runs the harness");
    assert!(out.status.success(), "harness failed: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("harness JSON");
    for s in v.get("subs").and_then(|f| f.as_array()).expect("subs array") {
        if s.get("name").and_then(|n| n.as_str()) == Some(sub_name) {
            return s.get("why").and_then(|w| w.as_str()).unwrap_or("").to_string();
        }
    }
    panic!("no sub {sub_name} in the harness output");
}

/// Tamper 3 (log-tamper) in CORE scope: the flipped wardend doc must not
/// move the snp fact (the snp channel never reads it), while the fold
/// DOES change (the wardend doc bytes are fold input): Rust errors the
/// tpm2 channel with no tpm facts, JS rolls tpm_quote to FAILED. The
/// wardend-side rejection (Rust plugin error <-> JS FAILED) is asserted
/// by the plugin's own agreement test.
#[test]
fn log_tamper_breaks_the_fold_on_both() {
    let g = fixture("golden.log-tamper.json");
    let (rust, errors) = rust_facts(&g);
    assert_eq!(rust.get("memory_encryption").map(String::as_str), Some("PROVEN"));
    assert!(
        errors.iter().any(|e| e.starts_with("tpm2:")),
        "the wardend doc bytes are fold input: the flip must break the Rust fold: {errors:?}"
    );
    assert!(
        !rust.contains_key("tpm_quote"),
        "a rejected tpm2 channel emits no tpm facts: {rust:?}"
    );
    let js = js_facts(&g);
    assert_eq!(js.get("memory_encryption").map(String::as_str), Some("PROVEN"));
    assert_eq!(js.get("tpm_quote").map(String::as_str), Some("FAILED (mapped)"));
    assert_eq!(js.get("wardend_state_chain").map(String::as_str), Some("FAILED (mapped)"));
}

/// The status tamper in CORE scope (the status cascade). Two properties,
/// both cross-verifier:
/// 1. The loud daemon_account fact: the fixture ships a tpm2=Failed row
///    (the transport's rewrite), and verify_bundle MUST render it as a
///    DEGRADED `channel.tpm2.daemon_account` fact with the reason text,
///    from the BUNDLE (the account is data, never a verifier output).
///    The JS verifier's page module for the account display ships later
///    (the D6 render lane) — the documented placement divergence; the
///    REJECTION-side agreement (wardend FAILED) is pinned in the plugin's
///    status_tamper_rejected_by_both.
/// 2. Independence: the rewrite touches only the status section, so the
///    snp/tpm2 hardware verdicts must NOT move — Rust and JS agree exactly
///    on what the rewrite leaves alone (PROVEN snp both sides; the tpm
///    fold-damage is the wardend signature's job, asserted in the plugin).
#[test]
fn status_rewrite_renders_loud_and_leaves_hardware_facts_alone() {
    let g = fixture("golden.status-tamper.json");
    #[cfg(feature = "system-health")]
    let _ = typed_envelope(&g);
    assert_identity_leaf_claim_explicit(&g, false);
    let (rust, errors) = rust_facts(&g);
    // The loud account row (with the misdiagnosis reason preserved).
    assert_eq!(
        rust.get("channel.tpm2.daemon_account").map(String::as_str),
        Some("DEGRADED"),
        "the failed status row must render loud regardless of channel verdicts: {rust:?}"
    );
    // The Collected rows get NO extra fact (self-destructing claims).
    assert!(
        !rust.contains_key("channel.snp.daemon_account"),
        "a Collected claim gets no daemon_account row: {rust:?}"
    );
    // Hardware independence: snp verifies exactly as on the golden (the
    // status section is not fold input for the snp channel).
    assert_eq!(
        rust.get("memory_encryption").map(String::as_str),
        Some("PROVEN"),
        "the status rewrite must not touch snp (errors: {errors:?})"
    );
    // tpm2 stays clean in core scope: the tpm fold reads the other
    // channels' ROWS (the PCR22 chain), never the status section, so the
    // rewrite leaves it exactly as on the golden. The status fold lives
    // ONLY in the wardend signature (asserted in the plugin's test).
    assert_eq!(
        rust.get("tpm_quote").map(String::as_str),
        Some("PROVEN"),
        "the tpm2 fold reads rows, not status: unaffected (errors: {errors:?})"
    );
    // JS agreement on the untouched facts: identical verdicts.
    let js = js_facts(&g);
    assert_eq!(js.get("memory_encryption").map(String::as_str), Some("PROVEN"));
    assert_eq!(js.get("tpm_quote").map(String::as_str), Some("PROVEN"));
    // And the REJECTION crosswalk (independent of the wardend verifier
    // ownership): the core registry cannot verify the wardend channel, but
    // the JS verifier reads the rewritten account against the signature
    // and rolls FAILED — the same rejection the plugin test pins from the
    // Rust side.
    assert_eq!(
        js.get("wardend_state_chain").map(String::as_str),
        Some("FAILED (mapped)"),
        "the browser must reject the rewritten account through the v2 fold"
    );
}
