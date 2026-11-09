//! demo: the STAGING DEMO quickstart page (operator directive 2026-11-09).
//!
//! One self-contained downloadable document: the SAME verifier core the
//! single-file pivot ships (byte-for-byte, reused not forked), wrapped in a
//! loud staging envelope plus a replicate-me block: the AMI id + the exact
//! user-data blob + the run-instances command, BAKED at build time from
//! assets/demo/manifest.json so a downloaded file carries its own replicate
//! inputs with zero fetch.
//!
//! Tier honesty is the design center: the attestation facts render through the
//! browser verifier at their real tiers; the replicate block is plainly labeled
//! displayed instructions ("claims a stranger copies", never a PROVEN costume,
//! never tier-elevated). The staging banner states that a green padlock on
//! staging proves nothing about production, so the padlock never travels
//! without its label.
//!
//! Gates (all TESTED, not claimed):
//!   * demo_sha256_matches_bytes           pin == sha256(embedded bytes).
//!   * artifact_regenerated_matches_committed  combiner --check exit 0.
//!   * artifact_carries_verifier_bytes     the embedded HTML contains the
//!     single-file verify.js VERBATIM, and with it the service worker's crypto
//!     region byte-exact: one verifier, three envelopes (SW, pivot, demo), the
//!     parity chains through.
//!   * tier_honesty_wording                the staging disclaimer, the
//!     display-of-instructions label, and the placeholder loudness all ship.
//!
//! PLACEHOLDER BUILD: manifest values are pending squid's launch; when the
//! real AMI/user-data land, edit ONLY manifest.json, re-run the combiner, and
//! re-derive this pin from the measured artifact (the regenerate gate fails
//! until all three agree).

/// The combined demo document (text/html; the bytes baked into the binary).
pub const DEMO_HTML: &str = include_str!("../assets/demo/index.html");

/// Hex SHA-256 of DEMO_HTML's bytes; a test recomputes and asserts this.
/// DERIVED from the spliced bytes (measured after the combiner run), never
/// hand-copied. PLACEHOLDER BUILD value; the regenerate gate forces a re-pin
/// when the real manifest values land.
pub const DEMO_SHA256: &str = "5f19a1ab9c7560d0b327ec280e1d561a8a361e7aa8fd40556f1ef5da7410fcec";

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root")
    }

    fn asset(rel: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/assets")
                .join(rel),
        )
        .expect("asset present")
    }

    #[test]
    fn demo_sha256_matches_bytes() {
        let h = hex(&Sha256::digest(DEMO_HTML.as_bytes()));
        assert_eq!(
            DEMO_SHA256, h,
            "DEMO_SHA256 const is stale; recompute sha256 of demo/index.html"
        );
    }

    #[test]
    fn artifact_regenerated_matches_committed() {
        let root = repo_root();
        let out = std::process::Command::new("node")
            .arg("fixtures/demo/combiner.js")
            .arg("--check")
            .current_dir(&root)
            .output()
            .expect("run demo combiner --check");
        assert!(
            out.status.success(),
            "demo combiner --check failed (index.html is stale):\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn artifact_carries_verifier_bytes() {
        // The demo reuses the single-file verify.js VERBATIM (one verifier,
        // two envelopes), and the pivot's crypto region is byte-identical to
        // the service worker's (its own parity gate proves that), so the demo
        // artifact transitively carries the SHIPPED crypto region. Assert both
        // links HERE so the demo lane fails loudly if either chain breaks.
        let pivot = asset("single_file/verify.js");
        assert!(
            DEMO_HTML.as_bytes().windows(pivot.len()).any(|w| w == pivot.as_slice()),
            "demo index.html does not carry the single-file verify.js verbatim"
        );
        let sw = asset("system_health/verify.js");
        const RUNVERIF: &[u8] =
            b"// -----------------------------------------------------------------------------\n// runVerification: THE verifier";
        let i = sw
            .windows(RUNVERIF.len())
            .position(|w| w == RUNVERIF)
            .expect("runVerification banner present");
        let crypto = &sw[..i];
        assert!(
            DEMO_HTML.as_bytes().windows(crypto.len()).any(|w| w == crypto),
            "demo index.html does not carry the service worker's crypto region byte-exactly"
        );
    }

    #[test]
    fn tier_honesty_wording() {
        let f = DEMO_HTML;
        // The staging banner states the padlock caveat (chipmunk: label it
        // staging LOUDLY).
        assert!(f.contains("this page is STAGING"), "staging banner missing");
        assert!(
            f.contains("green padlock here proves nothing about production"),
            "padlock disclaimer missing"
        );
        // The replicate block is labeled displayed-instructions, not attested.
        assert!(
            f.contains("displayed claims, not attested facts"),
            "replicate block lost its tier label"
        );
        // Placeholder builds must SHOUT that they are placeholders (a silent
        // placeholder shipping as a real quickstart is the failure mode).
        assert!(
            f.contains("PENDING"),
            "placeholder build lost its loud PENDING markers"
        );
    }

    #[test]
    fn manifest_is_the_sole_home_of_the_strings() {
        // The combiner's design rule: manifest.json is the ONLY place the
        // AMI/user-data strings live. The artifact must carry them (escaped as
        // needed), and the shell must carry sentinels only (no values).
        let manifest_raw = asset("demo/manifest.json");
        let m: serde_json::Value = serde_json::from_slice(&manifest_raw).expect("manifest json");
        let ami = m["ami_id"].as_str().expect("ami_id");
        assert!(DEMO_HTML.contains(ami), "artifact missing the manifest AMI id");
        let shell = String::from_utf8(asset("demo/shell.html")).expect("utf8 shell");
        assert!(
            shell.contains("{{AMI_ID}}") && !shell.contains("ami-"),
            "shell must carry the sentinel, not a baked value"
        );
    }
}
