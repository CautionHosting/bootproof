//! single_file: the canonical bootproof.html (the single-file pivot).
//!
//! One self-contained document: the verifier core + the System Health CSS +
//! the pending-first markup, inlined. No service worker, no /verify.js, no
//! separate stylesheet. The three reviewable, operator-named SOURCES
//! (assets/single_file/bootproof.html + bootproof.css + bootproof.js) are
//! spliced by the deterministic combiner (fixtures/single_file/combiner.js)
//! into the delivered artifact at assets/dist/bootproof.html, which is
//! committed and embedded with include_str!. The dist/ directory exists so
//! the artifact can never be confused with a source.
//!
//! PENDING-FIRST RENDER LAW (the operator's ruling, 2026-11-09): the
//! delivered document carries EVERY attribute row already painted with
//! status PENDING in its static bytes, before any fetch and before any
//! JavaScript runs. A JS-disabled browser reads a complete table of honest
//! not-yets. The flip engine in bootproof.js then flips each row to its own
//! verdict as the check that owns it completes; rows a finished pass never
//! reached flip to NOT PROVEN with the reason. The static rows include the
//! lifecycle rows the unit demo watches (user_data, seal_state, cert_chain +
//! the identity_link.* per-cert rows): the page is the witness surface for
//! the hot-add -> cert-issue -> seal flow.
//!
//! Why three sources and one artifact: the artifact is a generated delivery
//! format (a browser must fetch one file); the sources are the review surface
//! a human reads and diffs. The combiner is a PURE TEXTUAL SPLICE: it never
//! mutates the verifier bytes. That property is what lets the crypto region
//! of the single-file verifier be byte-for-byte the service-worker verifier's
//! crypto region, and it is asserted by tests, not claimed:
//!   * bootproof_sha256_matches_bytes  pins the const to the embedded bytes.
//!   * artifact_regenerated_matches_committed  runs the combiner --check: the
//!     committed artifact is exactly what the sources splice to.
//!   * crypto_region_byte_parity_with_service_worker  the single-file verifier's
//!     crypto region (everything before runVerification) is byte-identical to
//!     the system_health service worker's, so the derivation is proven.
//!   * artifact_carries_verifier_crypto_bytes  the embedded HTML literally
//!     contains those same crypto bytes (the splice was not lossy).
//!   * artifact_is_pending_first  every static row in the delivered bytes
//!     ships PENDING, the sentinels are gone (both spliced), and the rows
//!     the unit-lifecycle demo watches exist as first-class static rows.
//!   * row_parity_with_verifier  the node row_parity_contract runs over the
//!     shell + the flip engine: every row the verifier can emit exists as a
//!     static pending row, in both directions.

/// The combined single-file document (text/html; the bytes baked into the
/// binary, immutable, served verbatim).
pub const BOOTPROOF_HTML: &str = include_str!("../assets/dist/bootproof.html");

/// Hex SHA-256 of BOOTPROOF_HTML's bytes; a test recomputes and asserts this.
/// DERIVED from the spliced bytes (sha256sum of the generated artifact, measured
/// by the combiner), NOT hand-copied; never bake a historical value here. The
/// single-file artifact is a NEW delivery form, so this hash is independent of
/// the service-worker SW_SHA256 by construction (one file vs two files).
/// On-chain value: 88630e3b (T-E3 trunc crash-safe: trunc() fails closed to
/// "not published" on an absent/null field instead of throwing. Before this an
/// absent envelope field (user_data, seal_state.state_hash, leaf.subject/issuer)
/// reached trunc -> j(undefined) -> JSON.stringify(undefined) returns the VALUE
/// undefined -> s.length threw, and because the metadata table is one
/// synchronous render pass that crash KILLED THE ENTIRE PAGE. A missing source
/// is an honest NOT PROVEN, never a dead page (AGENTS.md). Byte-for-byte parity
/// with the service-worker trunc guard; both surfaces gated by
/// fixtures/system_health/trunc_contract.js).
/// On-chain value: 4210f8a6 (the title pivot: page <title> renamed 'System
/// Health' -> 'Bootproof Verifier' in single_file + shell sources per operator
/// 02:44Z; h1 and all other bytes identical to 2db3ce4b). Predecessor chain:
/// 2db3ce4b (the conformance tree + ARCHITECTURE.md R2 proposal), 637503ad (T-E facts tier + honest footer: mapStatus maps
/// the server's "proven" to SERVER-ASSERTED — env.facts is unsigned display,
/// the last tier-blind green after T-B — fact rows gain r-/v-/w- witness ids,
/// and the footer claim narrows to the browser-verified proofs with the
/// SERVER-ASSERTED rows named as server-published, not attested).
/// Before that: 195680d4 (T-B trust tiers: renderSections' metadata table
/// flips presence-PROVEN => SERVER-ASSERTED, the F3 overclaim fix; the metadata
/// blob is unsigned server display, never browser-verified attestation).
/// Before that: 4760aa18 (the pending-first pivot: operator-named sources, the
/// static pending tables, the flip engine, the fleet_domains row; the artifact
/// moved to assets/dist/), then a3ba3240 (the first canonical bootproof.html).
/// On-chain value: f54e0b8a (D4/D3 digest v2 in the browser face: the doc
/// signature is judged under digest v2 bound to this view's nonce, a
/// v1-only signature reads FAILED with the retired-contract replay named,
/// the wardend.doc_nonce freshness row and wardend.user_data_attested tier
/// rows ship as static PENDING rows, and the fixture/docsig gates pin both
/// digest versions). Predecessor: 4210f8a6.
/// On-chain value: 65a71b65 (D4 rows-fold: canonicalDocBytesV2 gains the
/// bundle's OTHER channels' rows (drop/swap close); the wardend row is
/// excluded, every other row present-tagged + SHA-256'd + content-sorted
/// into the v2 walk. The fixture's 68df3fae... v2 vector supersedes
/// 89b90855... and the empty-rows plugin golden rides c43c4a61. Predecessor:
/// f54e0b8a).
/// On-chain value: 038b3cbb (status cascade: canonicalDocBytesV2 gains the
/// daemon's channel_status fold (v2-only, LAST after the rows section; the
/// crypto-region block identical to the service-worker verify.js — measured
/// byte-identical, 78379-byte region — so the byte-parity test stays green).
/// The fold moves the fixture v2 vector 36320364 -> 5e25f96c and the plugin
/// empty-rows golden 554a8a18 -> 08a995c1; v1 stays byte-identical (the
/// status section entered v2 ONLY). Regenerated by
/// fixtures/single_file/combiner.js, measured by the combiner (123694
/// bytes). Predecessor: bfbb6d14).
/// On-chain value: 2a699931 (bake-11 SPKI tail fold: snp.identity_tail joins
/// the emitted row set + static PENDING rows (row parity 55 static/54
/// verifier names), bootproof.js mirrors the classify law byte-for-byte with
/// the service worker's verify.js, publishedPin threaded into checkSnp for
/// the same-attacker tier-label. Regenerated by
/// fixtures/single_file/combiner.js, measured by the combiner (126277
/// bytes). Predecessor: 038b3cbb).
pub const BOOTPROOF_SHA256: &str = "2a69993115ce3c55f99a777ad729f03028927a240c9a89e50213b2650076eb72";

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn repo_root() -> std::path::PathBuf {
        // crates/bootproof/src/system_health -> repo root is three up from src,
        // so: manifest dir (crates/bootproof) + ../.. = repo root.
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root")
    }

    fn asset(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/assets/single_file")
                .join(name),
        )
        .expect("single_file asset present")
    }

    fn sw_asset() -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/assets/system_health/verify.js"),
        )
        .expect("system_health verify.js present")
    }

    #[test]
    fn bootproof_sha256_matches_bytes() {
        let h = hex(&Sha256::digest(BOOTPROOF_HTML.as_bytes()));
        assert_eq!(
            BOOTPROOF_SHA256, h,
            "BOOTPROOF_SHA256 const is stale; recompute sha256 of bootproof.html"
        );
    }

    #[test]
    fn artifact_regenerated_matches_committed() {
        // The regenerate==committed gate: run the deterministic combiner in
        // --check mode and require exit 0. If dist/bootproof.html drifts from
        // (bootproof.html + bootproof.css + bootproof.js), the combiner exits
        // nonzero and this test fails. Node is already a test dependency of
        // the lane (fixtures/system_health/harness.js).
        let root = repo_root();
        let out = std::process::Command::new("node")
            .arg("fixtures/single_file/combiner.js")
            .arg("--check")
            .current_dir(&root)
            .output()
            .expect("run combiner --check");
        assert!(
            out.status.success(),
            "combiner --check failed (dist/bootproof.html is stale):\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The byte-parity boundary: everything in the verifier up to the
    /// runVerification banner is the crypto region (trust roots,
    /// canonicalizers, the four channel checks). The pivot and the service
    /// worker must be byte-identical there. The boundary is DERIVED from the
    /// banner, never a hardcoded offset.
    const RUNVERIF: &[u8] =
        b"// -----------------------------------------------------------------------------\n// runVerification: THE verifier";

    fn crypto_region(js: &[u8]) -> &[u8] {
        let i = js
            .windows(RUNVERIF.len())
            .position(|w| w == RUNVERIF)
            .expect("runVerification banner present");
        &js[..i]
    }

    #[test]
    fn crypto_region_byte_parity_with_service_worker() {
        let sw = sw_asset();
        let pivot = asset("bootproof.js");
        let (sw_pre, pv_pre) = (crypto_region(&sw), crypto_region(&pivot));
        assert_eq!(
            sw_pre.len(),
            pv_pre.len(),
            "crypto region length drift ({} vs {} bytes)",
            sw_pre.len(),
            pv_pre.len()
        );
        assert_eq!(
            sw_pre, pv_pre,
            "single-file bootproof.js crypto region is NOT byte-identical to the \
             service worker's: the derivation property is broken"
        );
    }

    #[test]
    fn artifact_carries_verifier_crypto_bytes() {
        // The embedded artifact must literally contain the crypto region: the
        // combiner spliced it, it did not rewrite it. This is the derivation
        // gate at the DELIVERED-bytes level (not just the source level).
        let pivot = asset("bootproof.js");
        let pre = crypto_region(&pivot);
        assert!(
            BOOTPROOF_HTML.as_bytes().windows(pre.len()).any(|w| w == pre),
            "bootproof.html does not contain the verifier crypto region verbatim"
        );
        // and the crypto region itself carries the shipped trust roots (the same
        // anchors the drift-killer test checks on SW):
        assert!(pre
            .windows(b"9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9".len())
            .any(|w| w == b"9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9"));
        assert!(pre
            .windows(b"0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3".len())
            .any(|w| w == b"0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3"));
    }

    #[test]
    fn footer_states_measurement_separate_from_binding() {
        // Doctrine gate: the footer must keep the MEASUREMENT sentence and the
        // EXTERNAL-BINDING sentence separate, and must never word the artifact as
        // self-proving ("contains its identity" / a PROVEN self-claim).
        let f = BOOTPROOF_HTML;
        assert!(
            f.contains("measured its own served bytes as"),
            "footer lost the measurement sentence"
        );
        assert!(
            f.contains("checked") && f.contains("<em>outside</em> this page"),
            "footer lost the external-binding sentence"
        );
        // never the provenance-in-a-PROVEN-costume wording:
        assert!(!f.contains("this file contains its identity"));
    }

    /// Every static row line in the delivered bytes: (id, the whole line).
    fn static_rows() -> Vec<(String, String)> {
        let mut out = Vec::new();
        for line in BOOTPROOF_HTML.lines() {
            let l = line.trim_start();
            if let Some(rest) = l.strip_prefix("<tr id=\"r-") {
                if let Some(end) = rest.find('"') {
                    out.push((rest[..end].to_string(), l.to_string()));
                }
            }
        }
        out
    }

    #[test]
    fn artifact_is_pending_first() {
        // The render law at the DELIVERED-bytes level: every static row ships
        // PENDING (never a pre-baked verdict), the splice sentinels are gone
        // (both sources really were inlined), and the unit-lifecycle rows the
        // operator watches exist as first-class static rows.
        let rows = static_rows();
        assert!(
            rows.len() >= 50,
            "expected the full pending row set (>= 50 static rows), found {}",
            rows.len()
        );
        let pending_chip = |id: &str| format!("<span class=\"verdict pd\" id=\"v-{id}\">PENDING</span>");
        for (id, line) in &rows {
            assert!(
                line.contains(&pending_chip(id)),
                "static row {id} does not ship PENDING: {line}"
            );
            assert!(
                line.contains("class=\"pd\""),
                "static row {id} lost its pending row class"
            );
        }
        // Sentinels spliced out entirely.
        assert!(!BOOTPROOF_HTML.contains("{{BOOTPROOF_CSS}}"), "CSS sentinel survived the splice");
        assert!(!BOOTPROOF_HTML.contains("{{BOOTPROOF_JS}}"), "JS sentinel survived the splice");
        // The lifecycle rows (chipmunk's addendum, the demo's witness set).
        for want in ["user_data", "seal_state", "cert_chain", "fleet_domains", "identity_link.pin"] {
            assert!(
                rows.iter().any(|(id, _)| id == want),
                "the delivered page has no static {want} row"
            );
        }
    }

    #[test]
    fn shell_and_artifact_agree_on_row_ids() {
        // The shell source and the delivered artifact must carry the SAME
        // static row-id set: the flip engine flips by id, so a row that only
        // exists in one of them is a silent gap. (The third direction,
        // verifier-emitted names vs static ids, is the node parity contract;
        // this closes the shell-vs-delivery direction in Rust.)
        let shell = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/assets/single_file/bootproof.html"),
        )
        .expect("shell source present");
        let ids_in = |bytes: &[u8]| -> Vec<String> {
            let text = std::str::from_utf8(bytes).expect("utf8 sources");
            let mut ids: Vec<String> = Vec::new();
            for line in text.lines() {
                let l = line.trim_start();
                if let Some(rest) = l.strip_prefix("<tr id=\"r-") {
                    if let Some(end) = rest.find('"') {
                        ids.push(rest[..end].to_string());
                    }
                }
            }
            ids.sort();
            ids
        };
        let mut art = BOOTPROOF_HTML
            .lines()
            .filter_map(|l| {
                let l = l.trim_start();
                let rest = l.strip_prefix("<tr id=\"r-")?;
                Some(rest[..rest.find('"')?].to_string())
            })
            .collect::<Vec<_>>();
        art.sort();
        assert_eq!(ids_in(&shell), art, "shell vs artifact static row-id drift");
    }

    #[test]
    fn row_parity_with_verifier() {
        // The both-directions parity contract between the static rows and
        // the row names bootproof.js can emit (including branch-only names
        // recovered by scanning the source). Node gate, same lane as the
        // combiner gate.
        let root = repo_root();
        let out = std::process::Command::new("node")
            .arg("fixtures/single_file/row_parity_contract.js")
            .current_dir(&root)
            .output()
            .expect("run row_parity_contract");
        assert!(
            out.status.success(),
            "row parity contract failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
