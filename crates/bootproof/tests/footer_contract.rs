// The local-verification-claim gate (AMI-2, 2026-11-08). The page must TELL
// the user that every fact was verified IN THEIR BROWSER by the service worker
// that rendered the page, with a working same-origin link to the verifier
// source. The link and the self-hash already existed; the EXPLICIT local claim
// did not, and this gate pins it so it cannot be softened back to a bare
// "verifier: N bytes" or silently dropped.
//
// Two sides, mirroring broadcast_contract.rs so neither half can drift:
//
//   * Rust side: byte greps over the embedded SW static pin (a) the footer
//     claim sentence, (b) the RELATIVE /verify.js.src href (same-origin, the
//     route already served - a new route or an absolute URL would break the
//     honest claim and the deploy), and (c) that the shell's own static link
//     text ("view verifier source") is preserved so the static and painted
//     pages read as one voice.
//   * JS side: run fixtures/system_health/footer_contract.js (node), which
//     drives the REAL render() and asserts the claim is verdict-independent
//     (it survives a FAILED row, because it is about the verifier's LOCATION,
//     not its verdict) and ABSENT when the SW has no self-hash to back it
//     (no self-hash, no claim). A pre-AMI-2 verify.js fails it.

#[cfg(feature = "system-health")]
mod footer {
    use bootproof::system_health::{SHELL, SW};
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn sw_footer_states_the_local_verification_claim() {
        // (a) The plain-language local claim: WHERE verification ran, not the
        // verdicts. Both halves of the sentence are pinned so a rewrite that
        // drops either the "in your browser" or the "rendered locally, not by
        // the server" half fails here.
        assert!(
            SW.contains("verified in your ") && SW.contains("browser by the service worker"),
            "the footer must state the local-verification claim in plain language"
        );
        assert!(
            SW.contains("rendered ") && SW.contains("locally") && SW.contains("not by the server"),
            "the footer must say the page was rendered locally, not by the server"
        );
    }

    #[test]
    fn sw_footer_links_the_verifier_source_relative_same_origin() {
        // (b) The link is RELATIVE (same-origin) to the already-served source
        // route. An absolute https:// URL would break same-origin and this
        // deploy's host mapping; a missing href breaks the claim's evidence.
        assert!(
            SW.contains("href=\"/verify.js.src\""),
            "the footer must link the verifier source at the RELATIVE /verify.js.src route"
        );
        // Not an absolute-URL version of the same link (which would not be
        // same-origin under the gate's host-resolver mapping).
        assert!(
            !SW.contains("https://verify") || !SW.contains("href=\"https://"),
            "the verifier-source link must be relative, not an absolute same-host URL"
        );
    }

    #[test]
    fn shell_static_link_voice_is_preserved() {
        // (c) The shell's static "view verifier source" link text stays so the
        // static placeholder page and the SW-painted footer use one voice. The
        // shell is otherwise untouched by AMI-2 (the gate's sw_sha capture
        // anchor lives here and must not move).
        assert!(
            SHELL.contains("view verifier source"),
            "the shell's static source link text must stay for static-vs-painted consistency"
        );
    }

    #[test]
    fn harness_asserts_claim_verdict_independence() {
        // Node is part of the documented test environment (the broadcast +
        // agreement gate precedent): a silently skipped harness is no gate.
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/system_health");
        let out = Command::new("node")
            .arg(fixtures.join("footer_contract.js"))
            .output()
            .expect("node runs footer_contract.js (node is part of the test environment)");
        assert!(
            out.status.success(),
            "footer claim contract harness failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
