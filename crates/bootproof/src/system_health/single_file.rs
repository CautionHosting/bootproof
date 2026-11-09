//! single_file: the FIRST canonical bootproof.html (the single-file pivot).
//!
//! One self-contained document: the verifier core + the System Health CSS + the
//! markup, inlined. No service worker, no /verify.js, no separate stylesheet.
//! The three reviewable SOURCES (shell.html, style.css, verify.js) live beside
//! this file and are spliced by the deterministic combiner
//! (fixtures/single_file/combiner.js) into the delivered artifact, which is
//! committed here and embedded with include_str!.
//!
//! Why three sources and one artifact: the artifact is a generated delivery
//! format (a browser must fetch one file); the sources are the review surface a
//! human reads and diffs. The combiner is a PURE TEXTUAL SPLICE: it never mutates
//! the verifier bytes. That property is what lets the crypto region of the
//! single-file verifier be byte-for-byte the service-worker verifier's crypto
//! region, and it is asserted by tests, not claimed:
//!   * bootproof_sha256_matches_bytes  pins the const to the embedded bytes.
//!   * artifact_regenerated_matches_committed  runs the combiner --check: the
//!     committed artifact is exactly what the sources splice to.
//!   * crypto_region_byte_parity_with_service_worker  the single-file verifier's
//!     crypto region (everything before runVerification) is byte-identical to
//!     the system_health service worker's, so the derivation is proven.
//!   * artifact_carries_verifier_crypto_bytes  the embedded HTML literally
//!     contains those same crypto bytes (the splice was not lossy).

/// The combined single-file document (text/html; the bytes baked into the
/// binary, immutable, served verbatim).
pub const BOOTPROOF_HTML: &str = include_str!("../assets/single_file/bootproof.html");

/// Hex SHA-256 of BOOTPROOF_HTML's bytes; a test recomputes and asserts this.
/// DERIVED from the spliced bytes (sha256sum of the generated artifact, measured
/// by the combiner), NOT hand-copied; never bake a historical value here. The
/// single-file artifact is a NEW delivery form, so this hash is independent of
/// the service-worker SW_SHA256 by construction (one file vs two files).
/// On-chain value: a3ba3240 (the first canonical bootproof.html, this commit).
pub const BOOTPROOF_SHA256: &str = "a3ba324079622c85253ec3a67c8597e48ffd81a70c1b27870e99e09feddb32a7";

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
        // --check mode and require exit 0. If bootproof.html drifts from
        // (shell.html + style.css + verify.js), the combiner exits nonzero and
        // this test fails. Node is already a test dependency of the lane
        // (fixtures/system_health/harness.js).
        let root = repo_root();
        let out = std::process::Command::new("node")
            .arg("fixtures/single_file/combiner.js")
            .arg("--check")
            .current_dir(&root)
            .output()
            .expect("run combiner --check");
        assert!(
            out.status.success(),
            "combiner --check failed (bootproof.html is stale):\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The byte-parity boundary: everything in verify.js up to the runVerification
    /// banner is the crypto region (trust roots, canonicalizers, the four channel
    /// checks). The pivot and the service worker must be byte-identical there.
    /// The boundary is DERIVED from the banner, never a hardcoded offset.
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
        let pivot = asset("verify.js");
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
            "single-file verify.js crypto region is NOT byte-identical to the \
             service worker's: the derivation property is broken"
        );
    }

    #[test]
    fn artifact_carries_verifier_crypto_bytes() {
        // The embedded artifact must literally contain the crypto region: the
        // combiner spliced it, it did not rewrite it. This is the derivation
        // gate at the DELIVERED-bytes level (not just the source level).
        let pivot = asset("verify.js");
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
}
