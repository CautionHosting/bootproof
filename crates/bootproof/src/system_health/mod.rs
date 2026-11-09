//! system_health: the embedded browser verifier bundle (the System Health
//! contract, docs/system-health.md v4). The HTML shell + the service-worker
//! verifier are committed statics embedded with include_str! so the browser
//! verifier ships from THIS crate alongside the Rust verifier it mirrors -
//! the two cannot drift (a test pins the SW bytes' hash).

/// The System Health HTML shell (title "System Health"; registers /verify.js).
pub const SHELL: &str = include_str!("../assets/system_health/shell.html");
/// The service-worker verifier source (application/javascript; the bytes
/// baked into the binary, immutable).
pub const SW: &str = include_str!("../assets/system_health/verify.js");
/// Hex SHA-256 of SW's bytes; a test recomputes and asserts this.
/// (2026-11-08 I-2b: rebumped for the whole-doc-signature gate + the
/// token-safe canonical_doc_digest mirror (the u64-precision-safe parse);
/// previous value b5f422f43d2ce451315ac877666342e6494fd4e0a47352bd42122a4a
/// 19ee9843 was the result.html contract fix, and before that
/// 5b270efc267e01b12d5145c94a508895381c1da57aabad18555c91f57ca23ad5.)
pub const SW_SHA256: &str = "fbd2bbb07d892c7f98ccf2b0899eac82e3ba965d5849c71408d8279a09f4967e";

pub mod schema;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sw_sha256_matches_bytes() {
        let h = hex(&Sha256::digest(SW.as_bytes()));
        assert_eq!(SW_SHA256, h, "SW_SHA256 const is stale; recompute sha256 of verify.js");
    }

    #[test]
    fn shell_has_title_and_app() {
        assert!(SHELL.contains("System Health"));
        assert!(SHELL.contains("id=\"app\""));
    }

    #[test]
    fn sw_is_nonempty_service_worker() {
        assert!(!SW.is_empty());
        assert!(SW.contains("addEventListener"));
    }

    /// PEM -> DER is the SHARED production walk (`crate::snp::pem_body_der`),
    /// not a test-local copy: the drift-killer then pins the EXACT function
    /// the bundle produces its `asvk`/`ark` anchors through, so a change to
    /// that walk cannot drift the served bytes away from the JS pins.
    #[test]
    fn js_anchors_match_rust_trust() {
        // The baked JS SPKI pins must equal the crate's own trust anchors.
        let ark = crate::spki::spki_pin(&crate::snp::pem_body_der(crate::snp::AMD_ARK_MILAN_PEM).expect("ARK pem body"))
            .expect("ARK spki pin");
        let asvk = crate::spki::spki_pin(&crate::snp::pem_body_der(crate::snp::AMD_ASVK_MILAN_PEM).expect("ASVK pem body"))
            .expect("ASVK spki pin");
        let want_ark = "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9";
        let want_ask = "66450a123ea5876206df67f2514a4fea224c0f63b18313423078b0edc4535e33";
        assert_eq!(ark.as_str(), want_ark, "ARK pin drift between JS and Rust");
        assert_eq!(asvk.as_str(), want_ask, "ASVK pin drift between JS and Rust");
        // and the JS source must literally carry these strings:
        assert!(SW.contains(want_ark));
        assert!(SW.contains(want_ask));
    }
}
