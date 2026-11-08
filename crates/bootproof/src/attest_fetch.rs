//! `bootproof attest-fetch` — the generic, neutral, UNAUTHENTICATED remote
//! attester (the CLI layer's neutrality instrument; see AGENTS.md "The CLI
//! layering + neutrality principle").
//!
//! Point it at ANY server that bears a `bootproof::wire::Bundle`, pull the
//! bundle over a fresh challenge nonce, and verify it through
//! [`crate::engine::verify_bundle`] with the registry-driven default verifier
//! set: channels are selected by the bundle's OWN evidence, never by a
//! hardcoded name match, so a bundle from any platform (our own seald face,
//! a turnkey TVC, any future plugin) verifies its own channels, and what it
//! lacks is an honest absent fact, never a silent drop.
//!
//! Two faces, both carrying a `wire::Bundle`:
//!
//! - `--frame <host:port>`: the len-first framed admin face (seald's
//!   `admin.sock`, wardend's loopback TCP bridge). Reuses
//!   [`crate::proxy::attest_roundtrip`] verbatim; the reply is the envelope
//!   JSON whose top-level `bundle` key carries the proof.
//! - `--url <http(s)://...>`: an HTTP face that answers
//!   `POST {"nonce": "<b64>"}` with EITHER a bare `Bundle` JSON (the old
//!   bootproofd `POST /attestation` shape, the same precedent verify set) OR
//!   the envelope JSON (`{"bundle": ..., ...}`, the bastiond `/health/api`
//!   shape). Detection is top-level key presence, nothing else.
//!
//! THE SECURITY MODEL (stated in the help text too, per the ruling): the
//! transport is UNAUTHENTICATED. Integrity comes from the bundle's own
//! signatures plus the fresh-nonce binding (a captured bundle fails the
//! replay guard); confidentiality and staleness-resistance are the TUNNEL's
//! job (e.g. `ssh -L` to a loopback admin face). `--frame` refuses any
//! non-loopback address unless the operator passes `--allow-remote`: the
//! loopback guard is a CLI-layer ruling (the proxy's own policy carries no
//! loopback field; `proxy.rs` stays byte-identical), because a CLI talking
//! to an arbitrary host over an unauthenticated frame socket must be an
//! explicit operator choice, never the default.
//!
//! The exit-code contract (the doctrine-critical classification; three-way
//! so honest degradation never cries wolf):
//!
//! - `0`: fetch ok AND no channel FAILED. NOT PROVEN facts are tolerated
//!   (printed loudly on stderr) — a tpm-only or snp-only node is a healthy
//!   honest node, and conflating NOT PROVEN with FAILED would fail exactly
//!   the honest-degrade reality the whole program exists to render.
//! - `1`: fetch ok but at least one channel FAILED verification, an unknown
//!   channel is present, OR a `--require-channel` channel is absent
//!   (operator-selected strictness: requiring turns honest-absent into a
//!   failing run).
//! - `2`: transport / parse / nonce error — NOTHING was verified, so no
//!   verdict (of any flavor) is meaningful.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine as _;

use crate::engine::{self, VerifyPolicy, VerifierRegistry};
use crate::proxy::{self, ProxyPolicy};
use crate::wire::{Bundle, Status};

/// Everything `attest-fetch` needs for one run. Built by the CLI from argv;
/// tests build it directly against loopback fakes.
pub struct FetchOpts {
    /// The framed admin face (`host:port`, len-first OP_ATTEST). Exactly one
    /// of `frame` / `url` must be set.
    pub frame: Option<String>,
    /// The HTTP face (`http(s)://host[:port]/path`, POST `{"nonce": b64}`).
    pub url: Option<String>,
    /// Operator opt-in to run `--frame` against a non-loopback address
    /// (unauthenticated transport: the tunnel must carry trust).
    pub allow_remote: bool,
    /// Pin the challenge nonce (64 hex chars) instead of generating a fresh
    /// one (reproducible captures; the replay guard still applies).
    pub nonce_hex: Option<String>,
    /// Channels whose ABSENCE fails the run (exit 1). Repeatable.
    pub require_channels: Vec<String>,
    /// Print the fetched bundle JSON before the facts table.
    pub bundle: bool,
    /// Per-phase timeout (frame connect/read/write; HTTP request).
    pub timeout: Duration,
}

/// Why a fetch failed BEFORE any verification happened: the exit-2 class
/// (transport / parse / nonce). Distinct from verification outcomes, which
/// are classified from [`engine::VerifiedFacts`], never from this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError(pub String);

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for FetchError {}

/// The three-way exit-code contract (see the module doc).
pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILED: i32 = 1;
pub const EXIT_NO_VERDICT: i32 = 2;

/// The default verifier registry: the core channels (snp + tpm2) only. The
/// CLI must never register a platform verifier (no wardend, no stagex): the
/// registry exists so `verify_bundle` selects by the bundle's own evidence,
/// and an unknown channel in the bundle is `verify_bundle`'s loud error,
/// not a CLI special case.
pub fn core_registry() -> VerifierRegistry {
    let mut reg = VerifierRegistry::new();
    reg.register(Box::new(crate::verify::snp::SnpVerifier));
    reg.register(Box::new(crate::verify::tpm2::Tpm2Verifier));
    reg
}

/// The strict frame-address guard (CLI-layer ruling; `proxy.rs` owns no
/// loopback policy). A `--frame` target must parse as an IPv4 `host:port`
/// AND be loopback, unless the operator passed `--allow-remote`. The error
/// names the opt-in so the failure is self-documenting.
pub fn check_frame_addr(addr: &str, allow_remote: bool) -> Result<(), FetchError> {
    let sock = addr
        .parse::<std::net::SocketAddrV4>()
        .map_err(|_| FetchError(format!("--frame wants an IPv4 host:port, got {addr:?}")))?;
    if !allow_remote && !sock.ip().is_loopback() {
        return Err(FetchError(format!(
            "--frame {addr} is not a loopback address: the frame transport is \
             UNAUTHENTICATED (integrity comes from the bundle's signatures + the \
             fresh nonce; confidentiality and staleness-resistance are the tunnel's \
             job). Tunnel it (e.g. ssh -L) or pass --allow-remote to opt in."
        )));
    }
    Ok(())
}

/// Parse one challenge nonce: `--nonce-hex` is exactly 64 hex chars (the
/// shared strict parser, the same rule the browser contract uses), absent
/// means 32 fresh random bytes.
pub fn challenge_nonce(nonce_hex: Option<&str>) -> Result<[u8; 32], FetchError> {
    match nonce_hex {
        Some(s) => proxy::parse_hex_nonce(s).map_err(FetchError),
        None => {
            let mut n = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut n);
            Ok(n)
        }
    }
}

/// The shared response-shape detection for BOTH faces: a bare `Bundle` JSON
/// (bootproofd precedent) OR an envelope JSON whose top-level `bundle` key
/// carries it (bastiond /health/api precedent). Detection is top-level key
/// presence and nothing else; anything else is an honest parse error (the
/// exit-2 class). A response that is valid JSON with neither shape (e.g. a
/// legacy NitroTPM `AttestResponse`) names the two accepted shapes so the
/// operator can tell "wrong face" from "broken server".
pub fn parse_bundle_json(text: &str) -> Result<Bundle, FetchError> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| FetchError(format!("response is not JSON: {e}")))?;
    if let Some(inner) = value.get("bundle") {
        return serde_json::from_value(inner.clone())
            .map_err(|e| FetchError(format!("envelope.bundle does not parse as a Bundle: {e}")));
    }
    serde_json::from_value(value).map_err(|e| {
        FetchError(format!(
            "response is neither a bare Bundle nor an envelope with a top-level \
             \"bundle\" key: {e}"
        ))
    })
}

/// One round-trip to the framed admin face: guard, fresh nonce, len-first
/// OP_ATTEST via the untouched [`crate::proxy`] seam, envelope bytes back,
/// shared detection parse. Every phase is bounded by [`ProxyPolicy`].
pub fn fetch_bundle_frame(opts: &FetchOpts, nonce: &[u8; 32]) -> Result<Bundle, FetchError> {
    let addr = opts.frame.as_deref().expect("caller checked face presence");
    check_frame_addr(addr, opts.allow_remote)?;
    let policy = ProxyPolicy {
        connect: opts.timeout,
        read: opts.timeout,
        write: opts.timeout,
        ..ProxyPolicy::default()
    };
    let bytes = proxy::attest_roundtrip(addr, nonce, &policy).map_err(|e| FetchError(e.reason()))?;
    let text = proxy::utf8_envelope(&bytes).map_err(|e| FetchError(e.reason()))?;
    parse_bundle_json(text)
}

/// One round-trip to an HTTP bundle face: POST `{"nonce": "<b64>"}` (the
/// base64 precedent `verify` set with bootproofd; the response may be a
/// bare Bundle or an envelope, see [`parse_bundle_json`]). Plain HTTP is a
/// first-class target (the tunnel may be the operator's job); https
/// validates the cert chain against the webpki roots but NOT against the
/// bundle signer identity — that identity link is the browser verifier's
/// ruling, not this increment's.
pub fn fetch_bundle_url(opts: &FetchOpts, nonce: &[u8; 32]) -> Result<Bundle, FetchError> {
    let url = opts.url.as_deref().expect("caller checked face presence");
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
    let body = serde_json::json!({ "nonce": nonce_b64 }).to_string();
    let agent = ureq::AgentBuilder::new().timeout(opts.timeout).build();
    let text = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let detail = resp.into_string().unwrap_or_default();
                FetchError(format!("attest-fetch request: {code} {detail}"))
            }
            e => FetchError(format!("attest-fetch request: {e}")),
        })?
        .into_string()
        .map_err(|e| FetchError(format!("attest-fetch response: {e}")))?;
    parse_bundle_json(&text)
}

/// The classification (the exit-code contract, minus the transport class):
/// FAILED verdicts come only from `verify_bundle` errors (a present-but-
/// failing or unknown channel) plus the operator's `--require-channel`
/// strictness (an absent required channel fails the RUN, though the engine
/// rendered it as an honest NOT PROVEN fact). NOT PROVEN alone is exit 0.
pub fn classify(
    bundle: &Bundle,
    verified: &engine::VerifiedFacts,
    require_channels: &[String],
) -> Result<(), Vec<String>> {
    let mut failures: Vec<String> = verified.errors.clone();
    let present: BTreeSet<&str> = bundle.evidence.iter().map(|e| e.channel.as_str()).collect();
    for req in require_channels {
        if !present.contains(req.as_str()) {
            failures.push(format!(
                "required channel {req:?} is absent from the bundle (honestly NOT \
                 PROVEN by default; --require-channel turns absence into a failure)"
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// The whole flow, end to end, returning the process exit code (never a
/// panic, never a bare Err for a verification outcome: exits are data).
pub fn run(opts: &FetchOpts, render: &dyn Fn(&[crate::wire::Fact]) -> String) -> anyhow::Result<i32> {
    // Exactly one face, checked before any network work.
    match (&opts.frame, &opts.url) {
        (Some(_), Some(_)) => {
            return Ok(fail("pick exactly one face: --frame OR --url, not both"))
        }
        (None, None) => return Ok(fail("pick a face: --frame <host:port> OR --url <http(s)://...>")),
        _ => {}
    }

    let nonce = match challenge_nonce(opts.nonce_hex.as_deref()) {
        Ok(n) => n,
        Err(e) => return Ok(fail(&e.to_string())),
    };

    // Fetch (the exit-2 class: anything that stops before verification).
    let bundle = match (opts.frame.as_ref(), opts.url.as_ref()) {
        (Some(_), _) => match fetch_bundle_frame(opts, &nonce) {
            Ok(b) => b,
            Err(e) => return Ok(fail(&e.to_string())),
        },
        (_, Some(_)) => match fetch_bundle_url(opts, &nonce) {
            Ok(b) => b,
            Err(e) => return Ok(fail(&e.to_string())),
        },
        _ => unreachable!("face presence checked above"),
    };

    // Replay guard: the fetched bundle must answer OUR nonce (a captured
    // bundle verifies cleanly against ITS nonce, so this is the freshness
    // binding — the same guard verify runs, ported to the neutral path).
    let answered: &[u8] = &bundle.nonce.0;
    if answered != nonce.as_slice() {
        return Ok(fail(
            "bundle nonce != challenge nonce (replay or MITM): NOTHING verified",
        ));
    }
    if bundle.v != crate::wire::BUNDLE_V {
        return Ok(fail(&format!(
            "unsupported bundle version {}: NOTHING verified",
            bundle.v
        )));
    }

    if opts.bundle {
        println!("{}", serde_json::to_string_pretty(&bundle)?);
    }

    // Verify: the registry-driven engine, default policy (no required
    // channels by default — --require-channel is the CLI-side strictness
    // layer, per the ruling, so the engine's honest NOT PROVEN rendering
    // stays intact for operators who did not ask for strictness).
    let registry = core_registry();
    let verified = engine::verify_bundle(&bundle, &VerifyPolicy::default_policy(), &registry);

    // Render, then classify.
    let face = opts
        .frame
        .as_deref()
        .map(|a| format!("frame://{a}"))
        .or_else(|| opts.url.clone())
        .unwrap_or_default();
    println!("\nbootproof attest-fetch {face}\n");
    println!("{}", render(&verified.facts));
    let not_proven = verified
        .facts
        .iter()
        .filter(|f| f.status == Status::NotProven)
        .count();
    if not_proven > 0 {
        // Honest degradation, printed loudly (the exit-0 doctrine: NOT
        // PROVEN is a true verdict, not a failure — but never a quiet one).
        eprintln!(
            "[attest-fetch] {not_proven} fact(s) NOT PROVEN (honest degrade; \
             --require-channel turns an absent channel into a failure)"
        );
    }
    match classify(&bundle, &verified, &opts.require_channels) {
        Ok(()) => Ok(EXIT_OK),
        Err(failures) => {
            println!("\nFAILED:");
            for f in &failures {
                println!("  {f}");
            }
            Ok(EXIT_FAILED)
        }
    }
}

/// The exit-2 rendering: the reason on stderr, no verdict claim anywhere.
fn fail(reason: &str) -> i32 {
    eprintln!("[attest-fetch] {reason}");
    EXIT_NO_VERDICT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{SlotLink, Tpm2Verified, Verified, Verifier};
    use crate::protocol;
    use crate::proxy::OP_ATTEST;
    use crate::wire::{B64, Evidence, Fact, Node, Status, BUNDLE_V};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A bundle shape the CORE has zero knowledge of: the channel name
    /// ("turnkey-tee") and its doc bytes are invented in this test. Nothing
    /// in bootproof knows what a turnkey-tee is — that is the point.
    fn turnkey_bundle(nonce: &[u8; 32]) -> Bundle {
        Bundle {
            v: BUNDLE_V,
            nonce: B64::new(nonce.to_vec()),
            node: Node {
                id: "tvc.example".into(),
                platform: "third-party-tvc".into(),
            },
            evidence: vec![Evidence {
                channel: "turnkey-tee".into(),
                doc: B64::new(b"opaque third-party evidence".to_vec()),
                anchors: Default::default(),
            }],
            keys: None,
            metadata: None,
        }
    }

    /// A registry carrying a verifier for a channel NO CORE CODE knows.
    /// If attest-fetch's path is registry-driven (not a hardcoded
    /// "tpm2"/"snp" match), this verifier gets consulted and the verdict
    /// flows. If the path ever hardcodes names again, this test fails.
    struct TurnkeyVerifier;
    impl Verifier for TurnkeyVerifier {
        fn name(&self) -> &'static str {
            "turnkey-tee"
        }
        fn verify(
            &self,
            ev: &Evidence,
            nonce: &[u8; 32],
            _bundle: &Bundle,
        ) -> Result<Verified, String> {
            // Consume the evidence + nonce so the wiring is proven, not
            // stubbed: the doc bytes and the challenge must reach us.
            assert!(!ev.doc.0.is_empty());
            assert_eq!(nonce.len(), 32);
            Ok(Verified::Tpm2(Tpm2Verified {
                per_pcr: Vec::new(),
                ak_public: Vec::new(),
                sign_public: None,
                sign_policy: None,
                sign_pcrs: None,
                slot_link: SlotLink::NoSlotPcr,
                ek_cert: None,
            }))
        }
        fn facts(&self, _v: &Verified) -> Vec<Fact> {
            vec![Fact {
                name: "tee_vendor_claim".into(),
                value: "turnkey attested (mock)".into(),
                anchors: vec!["turnkey-tee".into()],
                status: Status::Proven,
            }]
        }
    }

    /// THE mandated neutrality test: a turnkey-shaped bundle with a channel
    /// the core has never heard of verifies through the registry, with zero
    /// platform knowledge in the fetch path. (The registry is injectable at
    /// this level precisely so neutrality is testable; the CLI's own
    /// [`core_registry`] stays snp+tpm2 and nothing else.)
    #[test]
    fn registry_drives_channels_not_fixture_names() {
        let nonce = [0x5a; 32];
        let bundle = turnkey_bundle(&nonce);

        // (a) With the core registry, the unknown channel is a LOUD engine
        // error (never a silent drop, never a CLI name-match special case).
        let v = engine::verify_bundle(
            &bundle,
            &VerifyPolicy::default_policy(),
            &core_registry(),
        );
        assert!(
            v.errors.iter().any(|e| e.contains("turnkey-tee")),
            "unknown channel must be reported loudly: {:?}",
            v.errors
        );
        assert!(classify(&bundle, &v, &[]).is_err(), "a failing channel fails the run");

        // (b) With a registry that KNOWS the channel (registered, not
        // hardcoded), the same bundle verifies clean. Zero core code
        // changed between (a) and (b): the registry drove it.
        let mut reg = VerifierRegistry::new();
        reg.register(Box::new(TurnkeyVerifier));
        let v = engine::verify_bundle(&bundle, &VerifyPolicy::default_policy(), &reg);
        assert!(v.errors.is_empty(), "{:?}", v.errors);
        assert_eq!(v.facts.len(), 1);
        assert_eq!(v.facts[0].status, Status::Proven);
        assert!(classify(&bundle, &v, &[]).is_ok());

        // (c) require-channel on a bundle that does not carry it: honest
        // engine pass, CLI-side strictness turns it into exit 1.
        assert!(classify(&bundle, &v, &["wardend".to_string()]).is_err());
    }

    #[test]
    fn response_detection_is_top_level_key_presence() {
        let nonce = [0x11; 32];
        let bare = serde_json::to_string(&turnkey_bundle(&nonce)).unwrap();
        let env = serde_json::json!({
            "bundle": turnkey_bundle(&nonce),
            "facts": [],
            "nonce": "11".repeat(32),
            "identity": { "attest_signer_spki_sha256": null, "leaf_pem_present": false },
            "metadata": {},
        })
        .to_string();
        assert_eq!(parse_bundle_json(&bare).unwrap().node.id, "tvc.example");
        assert_eq!(parse_bundle_json(&env).unwrap().node.id, "tvc.example");
        // Neither shape (a legacy serve-style NitroTPM response): honest
        // exit-2 error naming both accepted shapes.
        let wrong = r#"{"nonce":"ab","module_id":"m","document":"AAA"}"#;
        let e = parse_bundle_json(wrong).unwrap_err().to_string();
        assert!(e.contains("bare Bundle"), "{e}");
        assert!(e.contains("bundle\" key"), "{e}");
        let e = parse_bundle_json("not json").unwrap_err().to_string();
        assert!(e.contains("not JSON"), "{e}");
    }

    #[test]
    fn frame_guard_refuses_non_loopback_unless_opted_in() {
        assert!(check_frame_addr("127.0.0.1:8444", false).is_ok());
        assert!(check_frame_addr("127.0.9.9:1", false).is_ok(), "127/8 is loopback");
        let e = check_frame_addr("10.0.0.5:8444", false).unwrap_err().to_string();
        assert!(e.contains("--allow-remote"), "{e}");
        assert!(e.contains("UNAUTHENTICATED"), "transport warning in the error: {e}");
        assert!(check_frame_addr("10.0.0.5:8444", true).is_ok());
        assert!(check_frame_addr("nonsense", false).is_err());
    }

    #[test]
    fn nonce_challenge_is_strict_hex_or_random() {
        let n = challenge_nonce(Some(&"ab".repeat(32))).unwrap();
        assert_eq!(n, [0xab; 32]);
        assert!(challenge_nonce(Some("deadbeef")).is_err(), "wrong length is exit-2");
        assert!(challenge_nonce(Some(&"zz".repeat(32))).is_err(), "non-hex is exit-2");
        let a = challenge_nonce(None).unwrap();
        let b = challenge_nonce(None).unwrap();
        assert_ne!(a, b, "two fresh challenges must differ");
    }

    /// End-to-end over the FRAME face: a fake admin face answering the
    /// len-first OP_ATTEST request with the envelope JSON (the seald /
    /// wardend bridge shape, byte-for-byte the proxy's contract).
    #[test]
    fn frame_face_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).unwrap();
            let n = u32::from_be_bytes(len) as usize;
            let mut req = vec![0u8; n];
            stream.read_exact(&mut req).unwrap();
            // The request must be the len-first OP_ATTEST + nonce33 frame
            // (the admin-face order proxy::attest_roundtrip speaks): we
            // already consumed the 4-byte length, so `req` is tag + nonce.
            assert_eq!(req[0], OP_ATTEST);
            assert_eq!(req.len(), 33);
            let nonce: [u8; 32] = req[1..].try_into().unwrap();
            let env = serde_json::json!({ "bundle": turnkey_bundle(&nonce) }).to_string();
            // The reply: `[len][OP_ATTEST][envelope]` (the same order).
            stream
                .write_all(&protocol::encode_len_first(OP_ATTEST, env.as_bytes()))
                .unwrap();
            stream.flush().unwrap();
            nonce
        });
        let opts = FetchOpts {
            frame: Some(addr),
            url: None,
            allow_remote: false,
            nonce_hex: Some("cd".repeat(32)),
            require_channels: vec![],
            bundle: false,
            timeout: Duration::from_secs(5),
        };
        let bundle = fetch_bundle_frame(&opts, &[0xcd; 32]).unwrap();
        assert_eq!(bundle.node.id, "tvc.example");
        assert_eq!(&bundle.nonce.0[..], &[0xcd; 32][..]);
        assert_eq!(handle.join().unwrap(), [0xcd; 32]);
    }

    /// End-to-end over the HTTP face: a minimal fake bundle server answering
    /// POST {"nonce": b64} with a bare Bundle (the bootproofd precedent).
    #[test]
    fn url_face_end_to_end_bare_bundle() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read headers, then the JSON body per Content-Length.
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap() == 0 {
                    return;
                }
                buf.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&buf).to_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            if len > 0 {
                stream.read_exact(&mut body).unwrap();
            }
            // Echo the nonce: decode b64, answer a bundle bound to it.
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let nonce_b64 = json["nonce"].as_str().unwrap();
            let nonce = base64::engine::general_purpose::STANDARD.decode(nonce_b64).unwrap();
            let mut n = [0u8; 32];
            n.copy_from_slice(&nonce);
            let resp = serde_json::to_string(&turnkey_bundle(&n)).unwrap();
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                resp.len()
            );
            stream.write_all(out.as_bytes()).unwrap();
            stream.flush().unwrap();
        });
        let opts = FetchOpts {
            frame: None,
            url: Some(format!("http://{addr}/attest")),
            allow_remote: false,
            nonce_hex: None,
            require_channels: vec![],
            bundle: false,
            timeout: Duration::from_secs(5),
        };
        let n = [0x77; 32];
        let bundle = fetch_bundle_url(&opts, &n).unwrap();
        assert_eq!(&bundle.nonce.0[..], &[0x77; 32][..], "the server echoed OUR nonce");
    }

    /// The full run() flow against the fake frame face, asserting the
    /// THREE-WAY exit contract end to end (0 not exercised here: the
    /// turnkey channel is unknown to core_registry so the honest verdict is
    /// exit 1; the clean-0 path is the classify() unit test above).
    #[test]
    fn run_maps_outcomes_to_the_three_way_exit_contract() {
        // exit 2: no face.
        let mut opts = probe_opts();
        opts.frame = None;
        assert_eq!(run(&opts, &|_| String::new()).unwrap(), EXIT_NO_VERDICT);
        // exit 2: both faces.
        let mut both = probe_opts();
        both.url = Some("http://127.0.0.1:1/".into());
        assert_eq!(run(&both, &|_| String::new()).unwrap(), EXIT_NO_VERDICT);
        // exit 2: bad --nonce-hex.
        let mut bad = probe_opts();
        bad.nonce_hex = Some("nope".into());
        assert_eq!(run(&bad, &|_| String::new()).unwrap(), EXIT_NO_VERDICT);
        // exit 2: nonce mismatch (fake answers OUR nonce, so force a
        // mismatch by pinning a different one than the fake echoes: the
        // fake echoes the request bytes verbatim, so instead point at a
        // dead port -> transport class).
        let mut dead = probe_opts();
        dead.frame = Some("127.0.0.1:1".into());
        assert_eq!(run(&dead, &|_| String::new()).unwrap(), EXIT_NO_VERDICT);
        // exit 1: fetch ok, channel FAILED (turnkey-tee unknown to core).
        let face = fake_frame_face();
        let mut ok = probe_opts();
        ok.frame = Some(face);
        assert_eq!(run(&ok, &|_| "table".into()).unwrap(), EXIT_FAILED);
    }

    fn probe_opts() -> FetchOpts {
        FetchOpts {
            frame: Some("127.0.0.1:1".into()),
            url: None,
            allow_remote: false,
            nonce_hex: None,
            require_channels: vec![],
            bundle: false,
            timeout: Duration::from_millis(500),
        }
    }

    /// A persistent-ish fake admin face answering ONE request per connect,
    /// echoing the bundle bound to the request's nonce.
    fn fake_frame_face() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for _ in 0..4 {
                let Ok((mut stream, _)) = listener.accept() else { return };
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                let mut req = vec![0u8; n];
                if stream.read_exact(&mut req).is_err() {
                    return;
                }
                // `req` is the frame body (len already consumed): tag + nonce.
                if req[0] != OP_ATTEST || req.len() != 33 {
                    return;
                }
                let Ok(n) = <[u8; 32]>::try_from(&req[1..]) else { return };
                let env = serde_json::json!({ "bundle": turnkey_bundle(&n) }).to_string();
                let _ = stream.write_all(&protocol::encode_len_first(OP_ATTEST, env.as_bytes()));
                let _ = stream.flush();
            }
        });
        addr
    }
}
