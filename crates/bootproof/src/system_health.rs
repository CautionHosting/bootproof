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
pub const SW_SHA256: &str = "d021c94ce2b8f2806ff4969aa24a70097f3d373430acd044b4c179944671c11e";

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
}
