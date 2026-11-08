//! system_health: the embedded browser verifier bundle (the System Health
//! contract, docs/system-health.md v4). The HTML shell + the service-worker
//! verifier are committed statics embedded with include_str! so the browser
//! verifier ships from THIS crate alongside the Rust verifier it mirrors -
//! the two cannot drift (a test pins the SW bytes' hash).

/// The System Health HTML shell (title "System Health"; registers /verify.js).
pub const SHELL: &str = include_str!("assets/system_health/shell.html");
/// The service-worker verifier source (application/javascript; the bytes
/// baked into the binary, immutable).
pub const SW: &str = include_str!("assets/system_health/verify.js");
/// Hex SHA-256 of SW's bytes; a test recomputes and asserts this.
pub const SW_SHA256: &str = "5b270efc267e01b12d5145c94a508895381c1da57aabad18555c91f57ca23ad5";

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

    /// PEM -> DER: strip the armor lines and base64-decode the body.
    fn pem_to_der(pem: &[u8]) -> Vec<u8> {
        let body: String = pem
            .iter()
            .map(|b| *b as char)
            .collect::<String>()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .expect("test PEM is valid base64")
    }

    #[test]
    fn js_anchors_match_rust_trust() {
        // The baked JS SPKI pins must equal the crate's own trust anchors.
        let ark = crate::spki::spki_pin(&pem_to_der(crate::snp::AMD_ARK_MILAN_PEM))
            .expect("ARK spki pin");
        let asvk = crate::spki::spki_pin(&pem_to_der(crate::snp::AMD_ASVK_MILAN_PEM))
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
