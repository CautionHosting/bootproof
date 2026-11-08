// The page/SW message-contract gate (2026-11-08 regression): the live
// System Health page hung at "Verifying..." forever because broadcast()
// posted the rendered html as a TOP-LEVEL SIBLING of result while the shell
// reads d.result.html. The fix is one field (result.html), and this gate
// pins it from both sides so neither half can drift back:
//
//   * JS side: run fixtures/system_health/broadcast_contract.js (node),
//     which drives the REAL verify.js activate -> loop -> broadcast path
//     with a stubbed fetch + recording fake client, runs the shell handler
//     LOGIC against the recorded message, and drives the REAL sh-ping
//     reply. A pre-fix verify.js FAILS it (witnessed, attributable).
//   * Rust side: byte greps over the two embedded statics pin the exact
//     contract reads (the shell's r.html -> innerHTML and the SW's
//     result.html = render(result); plus the ABSENCE of the sibling post
//     shape), so a shell-side "fix" that moves the read instead of the
//     post fails here too.
//
// The shell is a static include_str! asset (no module system), so the
// harness mirrors its handler; this test is what binds that mirror to the
// real shell bytes.

#[cfg(feature = "system-health")]
mod contract {
    use bootproof::system_health::{SHELL, SW};
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn sw_posts_html_on_result_not_as_sibling() {
        // The single contract field: html rides ON result...
        assert!(
            SW.contains("result.html = render(result);"),
            "broadcast() must render onto result (the shell reads d.result.html)"
        );
        // ...and the pre-fix sibling shape must be gone from every post site.
        assert!(
            !SW.contains("result: result, html:"),
            "a post site still ships html as a top-level sibling (the pre-fix shape)"
        );
    }

    #[test]
    fn shell_reads_result_html_into_innerhtml() {
        // The shell half of the contract (the side the spec says NOT to
        // change): guard on type + result, then paint r.html.
        assert!(
            SHELL.contains("d.type !== \"system-health\" || !d.result"),
            "the shell must guard the message type + result presence"
        );
        assert!(
            SHELL.contains("if (el && r.html !== undefined) el.innerHTML = r.html;"),
            "the shell's paint read drifted; the harness mirror no longer matches"
        );
    }

    #[test]
    fn harness_drives_real_broadcast_and_ping_paths() {
        // Node is part of the documented test environment (the agreement
        // gate precedent): a silently skipped harness is no gate.
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/system_health");
        let out = Command::new("node")
            .arg(fixtures.join("broadcast_contract.js"))
            .output()
            .expect("node runs broadcast_contract.js (node is part of the test environment)");
        assert!(
            out.status.success(),
            "broadcast contract harness failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
