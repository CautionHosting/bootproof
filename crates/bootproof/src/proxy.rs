//! `proxy` — the bootproof-owned attest round-trip: the client side of the
//! attestation ADMIN FACE (a daemon's nonce->envelope listener: wardend's
//! `seald` today, any platform's equivalent tomorrow).
//!
//! This is the seam a wire owner (bastiond's `/health/api` today, the
//! generic bootproof CLI tomorrow) calls instead of hand-rolling the frame
//! codec, the nonce parser, the timeouts, and the error mapping. The failure
//! semantics are MOVED from wardend's `bastion/src/health.rs`, not invented:
//! every reason string this module produces is byte-identical to the one the
//! moved code produced for the same input (asserted in the equivalence
//! tests, which re-run the original code shapes side by side).
//!
//! The contract, unchanged by the move:
//!
//! - The nonce is VERBATIM. The browser generates 32 random bytes, the
//!   query carries 64 raw hex, this module parses it to the exact 32 bytes,
//!   and they go into `OP_ATTEST` untouched. A re-roll would silently break
//!   the anti-replay binding, so no code path here re-rolls: `parse_hex_nonce`
//!   either yields the caller's bytes or refuses with a 400-class reason.
//! - The envelope bytes are PASS-THROUGH. This module never parses,
//!   re-serializes, or "validates" the envelope: a proxy that checked
//!   signatures would be an unpinned third verifier turning
//!   signed-but-strange envelopes into gateway errors, which weakens the
//!   two-verifiers-agree model. The client verifies cryptographically; the
//!   pipe stays honest.
//! - Fail closed and bounded: every phase (connect / write / read) carries
//!   a timeout from [`ProxyPolicy`], a declared frame length beyond
//!   `max_frame` is refused BEFORE allocating, and every failure is a typed
//!   [`ProxyError`] that maps to a status ([`ProxyError::status`]) and a
//!   JSON body ([`ProxyError::json`]). Never a hang, never an empty 200.
//!
//! This module stops BELOW HTTP on purpose (the approved ruling): it owns
//! frames, the nonce, errors, and the status mapping AS DATA; the wire owner
//! owns HTTP bytes (status line, headers, `Cache-Control: no-store`). A
//! future non-HTTP consumer (a WSS tunnel, the CLI's socket mode) reuses the
//! exact same core.
//!
//! Transport is TCP (the documented admin-face decision: the loopback TCP
//! face is the one the wire owner is guaranteed to reach; a UDS seam stays
//! open behind this same function shape). Synchronous std-only: no tokio,
//! so an async consumer calls this through `spawn_blocking` without
//! bootproof's proxy core gaining a runtime dependency.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// The attestation admin face's request opcode (wardend's
/// `wardenctl::protocol::OP_ATTEST`; the same constant bastiond's moved
/// code used). NOTE: the admin face has its OWN opcode space, distinct from
/// the daemon<->hardware-owner socket's `protocol::OP_COLLECT` (the faces
/// are disjoint, so the shared numeric value is harmless and frozen).
pub const OP_ATTEST: u8 = 1;

/// The admin face's error reply opcode (the body is the refusal reason).
pub const OP_ERROR: u8 = 0xff;

/// The default response-frame cap (moved from bastiond's `MAX_FRAME`: an
/// oversized frame is a refusal, not an allocation of whatever the peer
/// declares). 8 MiB is far above any real envelope.
pub const DEFAULT_MAX_FRAME: usize = 8 * 1024 * 1024;

/// The default per-phase timeout (moved from bastiond's
/// `ROUNDTRIP_TIMEOUT`: attest production on real hardware is a live SNP
/// report + TPM quote round-trip, genuinely 10-30 s, and longer under
/// load; a page fetch must survive a slow-but-healthy backend. The
/// connection itself cannot wedge: the worst case is this bound, per phase).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// The bounds and cap one round-trip runs under. Clone/Copy so a wire owner
/// can build it once at startup and hand it per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyPolicy {
    /// The connect timeout (`TcpStream::connect_timeout`).
    pub connect: Duration,
    /// The socket read timeout (set on the stream after connect).
    pub read: Duration,
    /// The socket write timeout (set on the stream after connect).
    pub write: Duration,
    /// The response-frame cap, enforced BEFORE allocating the body.
    pub max_frame: usize,
}

impl Default for ProxyPolicy {
    fn default() -> Self {
        ProxyPolicy {
            connect: DEFAULT_TIMEOUT,
            read: DEFAULT_TIMEOUT,
            write: DEFAULT_TIMEOUT,
            max_frame: DEFAULT_MAX_FRAME,
        }
    }
}

/// One query parameter's value (first occurrence; the value is taken
/// verbatim, no decoding). The wire owner that parses HTTP query strings
/// uses this so the "nonce=" extraction rule (a prefix collision like
/// `nonceX=` must NOT match) is also owned here, not re-implemented.
pub fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix(key) {
            if let Some(v) = v.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// The nonce parser: exactly 64 hex characters, any case, into 32 bytes.
/// A wrong length, a non-hex character, or an empty value is an `Err` with
/// the reason (the 400 body). Percent-escapes are rejected rather than
/// decoded: a URL-encoded nonce is not the browser contract. Moved
/// byte-for-byte in behavior from bastiond's `parse_nonce`.
pub fn parse_hex_nonce(s: &str) -> Result<[u8; 32], String> {
    if s.is_empty() {
        return Err("empty nonce".to_string());
    }
    if s.bytes().any(|b| b == b'%') {
        return Err("the nonce must be raw hex, not percent-encoded".to_string());
    }
    if s.len() != 64 {
        return Err(format!(
            "the nonce must be 64 hex characters (32 bytes), got {}",
            s.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_val(s.as_bytes()[i * 2]).ok_or("the nonce is not hex")?;
        let lo = hex_val(s.as_bytes()[i * 2 + 1]).ok_or("the nonce is not hex")?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Why one round-trip failed. The variant is the CLASSIFICATION (what the
/// wire owner branches on / maps to a status); the carried string is the
/// contract reason, byte-identical to what the moved bastiond code produced
/// for the same failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// The nonce is missing, empty, the wrong length, not hex, or
    /// percent-encoded. The only 400-class failure (the client asked wrong).
    Nonce(String),
    /// The admin address is not `host:port` (v4).
    Addr(String),
    /// Connect failed (refused, unreachable): `connect {addr}: {io}`.
    Connect(String),
    /// A phase hit its [`ProxyPolicy`] timeout. The reason keeps the moved
    /// code's `{phase}: {io}` shape (a timeout is an io error at that
    /// phase), so the wire text is unchanged; the variant says why.
    Timeout(String),
    /// The request write or flush failed: `{phase}: {io}`.
    WriteFailed(String),
    /// A read hit EOF mid-frame (`read_exact` filled short):
    /// `{phase}: {io}`.
    ShortFrame(String),
    /// A read failed for a non-timeout, non-EOF reason: `{phase}: {io}`.
    ReadFailed(String),
    /// The declared frame length is refused (0 has no opcode byte; over
    /// `max_frame` is the cap). Refused BEFORE allocating the body. The
    /// reason is the moved code's single shared shape:
    /// `the response frame size is refused ({declared})`.
    FrameSize(usize),
    /// The backend refused with `OP_ERROR`: the reason body survives as
    /// `seald refused: {reason}` (the moved wording; "seald" is what the
    /// admin face is called on the wire today, frozen for compatibility).
    Refused(String),
    /// The response opcode is neither `OP_ATTEST` nor `OP_ERROR`.
    BadOpcode(u8),
    /// The envelope is not UTF-8 (no JSON can be produced from it).
    NotUtf8,
}

impl ProxyError {
    /// The contract reason string (the `{"error": ...}` value).
    pub fn reason(&self) -> String {
        match self {
            ProxyError::Nonce(r)
            | ProxyError::Addr(r)
            | ProxyError::Connect(r)
            | ProxyError::Timeout(r)
            | ProxyError::WriteFailed(r)
            | ProxyError::ShortFrame(r)
            | ProxyError::ReadFailed(r) => r.clone(),
            ProxyError::FrameSize(declared) => {
                format!("the response frame size is refused ({declared})")
            }
            ProxyError::Refused(r) => format!("seald refused: {r}"),
            ProxyError::BadOpcode(other) => {
                format!("unexpected response opcode {other}")
            }
            ProxyError::NotUtf8 => "seald returned a non-UTF-8 envelope".to_string(),
        }
    }

    /// The HTTP status THIS error maps to (as data; the wire owner renders
    /// the status line). A nonce problem is the client's (400); everything
    /// else is a backend/transport failure (502).
    pub fn status(&self) -> u16 {
        match self {
            ProxyError::Nonce(_) => 400,
            _ => 502,
        }
    }

    /// The frozen JSON error body (`{"error":"..."}`, with the moved
    /// code's exact escaping).
    pub fn json(&self) -> String {
        json_error(self.reason())
    }
}

/// The JSON error body (the contract's `{"error":"..."}`; the value is
/// escaped so a reason with quotes never yields invalid JSON). Moved from
/// bastiond's `json_error` verbatim; a wire owner that renders errors uses
/// this (or [`ProxyError::json`]) so the error SHAPE has one owner.
pub fn json_error(reason: impl AsRef<str>) -> String {
    let mut out = String::from("{\"error\":\"");
    for c in reason.as_ref().chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push_str("\"}");
    out
}

/// Interpret a round-trip result as the UTF-8 envelope text the wire owner
/// renders (the moved code's post-round-trip check, as a reusable
/// function so the reason string has one owner).
pub fn utf8_envelope(bytes: &[u8]) -> Result<&str, ProxyError> {
    std::str::from_utf8(bytes).map_err(|_| ProxyError::NotUtf8)
}

/// One `OP_ATTEST` round-trip to the admin face: connect, send
/// `[4-byte BE len][OP_ATTEST][nonce32]` (the len-first admin-frame order,
/// see [`crate::protocol::FrameOrder::LenFirst`]), read
/// `[4-byte BE len][OP_ATTEST][envelope JSON]` or
/// `[4-byte BE len][OP_ERROR][reason]`. Every phase is bounded by the
/// policy, so a wedged backend costs the timeout and nothing more. The
/// envelope bytes come back UNTOUCHED (pass-through, see the module doc).
///
/// The transport is TCP on the loopback admin face (the documented
/// decision; the UDS seam stays open for a later switch behind this same
/// function).
pub fn attest_roundtrip(
    addr: &str,
    nonce: &[u8; 32],
    policy: &ProxyPolicy,
) -> Result<Vec<u8>, ProxyError> {
    let sock: SocketAddrV4 = addr
        .parse::<SocketAddrV4>()
        .map_err(|_| ProxyError::Addr(addr_bad(addr)))?;
    let mut stream = match TcpStream::connect_timeout(&SocketAddr::V4(sock), policy.connect) {
        Ok(s) => s,
        Err(e) if is_timeout(&e) => {
            return Err(ProxyError::Timeout(format!("connect {addr}: {e}")))
        }
        Err(e) => return Err(ProxyError::Connect(format!("connect {addr}: {e}"))),
    };
    let _ = stream.set_read_timeout(Some(policy.read));
    let _ = stream.set_write_timeout(Some(policy.write));
    // The request: `[4-byte BE len][opcode][nonce]` (the shared codec's
    // len-first order; the 33-byte request declares 33).
    let frame = crate::protocol::encode_len_first(OP_ATTEST, nonce);
    stream
        .write_all(&frame)
        .map_err(|e| ProxyError::WriteFailed(write_reason("write attest request", &e)))?;
    stream
        .flush()
        .map_err(|e| ProxyError::WriteFailed(write_reason("flush attest request", &e)))?;
    // The response frame.
    let mut len_prefix = [0u8; 4];
    read_phase(&mut stream, &mut len_prefix, "read response length")?;
    let declared = u32::from_be_bytes(len_prefix) as usize;
    if declared == 0 || declared > policy.max_frame {
        return Err(ProxyError::FrameSize(declared));
    }
    let mut body = vec![0u8; declared];
    read_phase(&mut stream, &mut body, "read response body")?;
    // `declared > 0` is guaranteed above, so body[0] exists.
    match body[0] {
        OP_ATTEST => Ok(body[1..].to_vec()),
        OP_ERROR => Err(ProxyError::Refused(String::from_utf8_lossy(&body[1..]).into_owned())),
        other => Err(ProxyError::BadOpcode(other)),
    }
}

fn addr_bad(addr: &str) -> String {
    format!("the admin address {addr:?} is not host:port (v4)")
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

// The write phases have no timeout/EOF classification in the moved code
// (a failed write is a failed write); the helpers exist so the reason
// shapes are formatted in exactly one place.
fn write_reason(phase: &str, e: &std::io::Error) -> String {
    format!("{phase}: {e}")
}

/// `read_exact` with the moved code's failure classification: a timeout
/// yields `Timeout`, an EOF mid-fill yields `ShortFrame`, anything else
/// `ReadFailed`, each carrying the moved code's exact `{phase}: {io}`
/// reason string.
fn read_phase(
    stream: &mut TcpStream,
    buf: &mut [u8],
    phase: &str,
) -> Result<(), ProxyError> {
    match stream.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if is_timeout(&e) => Err(ProxyError::Timeout(format!("{phase}: {e}"))),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            Err(ProxyError::ShortFrame(format!("{phase}: {e}")))
        }
        Err(e) => Err(ProxyError::ReadFailed(format!("{phase}: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// The moved-code shapes, reproduced VERBATIM from wardend's
    /// `bastion/src/health.rs` (the pre-move original), so the equivalence
    /// gate compares the seam against the code it replaces, not against my
    /// memory of it. These are test-only oracles.
    mod original {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        pub const OP_ATTEST: u8 = 1;
        pub const OP_ERROR: u8 = 0xff;
        pub const MAX_FRAME: usize = 8 * 1024 * 1024;
        const ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(60);

        pub fn parse_nonce(s: &str) -> Result<[u8; 32], String> {
            if s.is_empty() {
                return Err("empty nonce".to_string());
            }
            if s.bytes().any(|b| b == b'%') {
                return Err("the nonce must be raw hex, not percent-encoded".to_string());
            }
            if s.len() != 64 {
                return Err(format!(
                    "the nonce must be 64 hex characters (32 bytes), got {}",
                    s.len()
                ));
            }
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                let hi = match s.as_bytes()[i * 2] {
                    b'0'..=b'9' => s.as_bytes()[i * 2] - b'0',
                    b'a'..=b'f' => s.as_bytes()[i * 2] - b'a' + 10,
                    b'A'..=b'F' => s.as_bytes()[i * 2] - b'A' + 10,
                    _ => return Err("the nonce is not hex".to_string()),
                };
                let lo = match s.as_bytes()[i * 2 + 1] {
                    b'0'..=b'9' => s.as_bytes()[i * 2 + 1] - b'0',
                    b'a'..=b'f' => s.as_bytes()[i * 2 + 1] - b'a' + 10,
                    b'A'..=b'F' => s.as_bytes()[i * 2 + 1] - b'A' + 10,
                    _ => return Err("the nonce is not hex".to_string()),
                };
                *byte = (hi << 4) | lo;
            }
            Ok(out)
        }

        pub fn json_error(reason: impl AsRef<str>) -> String {
            let mut out = String::from("{\"error\":\"");
            for c in reason.as_ref().chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push_str("\"}");
            out
        }

        pub fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
            for pair in query.split('&') {
                if let Some(v) = pair.strip_prefix(key) {
                    if let Some(v) = v.strip_prefix('=') {
                        return Some(v);
                    }
                }
            }
            None
        }

        pub fn attest_roundtrip(addr: &str, nonce: &[u8; 32]) -> Result<Vec<u8>, String> {
            let sock = match std::net::SocketAddr::V4(v4(addr)?) {
                sock => sock,
            };
            let mut stream = TcpStream::connect_timeout(&sock, ROUNDTRIP_TIMEOUT)
                .map_err(|e| format!("connect {addr}: {e}"))?;
            let _ = stream.set_read_timeout(Some(ROUNDTRIP_TIMEOUT));
            let _ = stream.set_write_timeout(Some(ROUNDTRIP_TIMEOUT));
            let mut payload = Vec::with_capacity(1 + 32);
            payload.push(OP_ATTEST);
            payload.extend_from_slice(nonce);
            let mut frame = Vec::with_capacity(4 + payload.len());
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            stream
                .write_all(&frame)
                .map_err(|e| format!("write attest request: {e}"))?;
            stream
                .flush()
                .map_err(|e| format!("flush attest request: {e}"))?;
            let mut len_prefix = [0u8; 4];
            stream
                .read_exact(&mut len_prefix)
                .map_err(|e| format!("read response length: {e}"))?;
            let declared = u32::from_be_bytes(len_prefix) as usize;
            if declared == 0 || declared > MAX_FRAME {
                return Err(format!("the response frame size is refused ({declared})"));
            }
            let mut body = vec![0u8; declared];
            stream
                .read_exact(&mut body)
                .map_err(|e| format!("read response body: {e}"))?;
            if body.is_empty() {
                return Err("empty response frame (no opcode)".to_string());
            }
            match body[0] {
                OP_ATTEST => Ok(body[1..].to_vec()),
                OP_ERROR => Err(format!(
                    "seald refused: {}",
                    String::from_utf8_lossy(&body[1..])
                )),
                other => Err(format!("unexpected response opcode {other}")),
            }
        }

        fn v4(addr: &str) -> Result<std::net::SocketAddrV4, String> {
            addr.parse::<std::net::SocketAddrV4>()
                .map_err(|_| format!("the admin address {addr:?} is not host:port (v4)"))
        }
    }

    /// Assert the seam's reason string is byte-identical to the original's
    /// for the same failing scenario (run BOTH against the same fixture).
    fn same_reason(seam: &ProxyError, original_err: String) {
        assert_eq!(seam.reason(), original_err);
    }

    /// A fake admin face: bind an ephemeral loopback listener and answer
    /// exactly one request frame with the raw bytes `reply_after_request`
    /// produces (the fake controls the FULL response bytes, so the
    /// equivalence tests can drive every failure shape).
    fn fake_seald<F>(f: F) -> String
    where
        F: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n == 0 || n > original::MAX_FRAME {
                    return;
                }
                let mut req = vec![0u8; n];
                if stream.read_exact(&mut req).is_err() {
                    return;
                }
                let out = f(&req);
                let _ = stream.write_all(&out);
                let _ = stream.flush();
            }
        });
        addr
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn nonce() -> [u8; 32] {
        [0xab; 32]
    }

    #[test]
    fn a_good_round_trip_returns_the_envelope_bytes_untouched() {
        let envelope = br#"{"bundle":{},"facts":[],"nonce":"ab"}"#.to_vec();
        let mut payload = vec![original::OP_ATTEST];
        payload.extend_from_slice(&envelope);
        let reply = frame(&payload);
        let addr = fake_seald(move |_| reply);
        let seam = attest_roundtrip(&addr, &nonce(), &ProxyPolicy::default()).unwrap();
        assert_eq!(seam, envelope);
    }

    #[test]
    fn the_request_frame_is_the_moved_shape_with_the_nonce_verbatim() {
        // The fake echoes back the NONCE bytes it received (skipping the
        // opcode), so the test can prove the seam sent exactly
        // `[len=33][OP_ATTEST][nonce32]` and never touched the nonce.
        let addr = fake_seald(|req| {
            let mut payload = vec![original::OP_ATTEST];
            payload.extend_from_slice(&req[1..]);
            frame(&payload)
        });
        let got = attest_roundtrip(&addr, &nonce(), &ProxyPolicy::default()).unwrap();
        assert_eq!(got, nonce().to_vec());
    }

    #[test]
    fn a_seald_refusal_maps_to_refused_with_the_moved_reason() {
        let reason = b"attest nonce is 0 bytes, expected 32";
        let mut payload = vec![original::OP_ERROR];
        payload.extend_from_slice(reason);
        let reply = frame(&payload);
        let addr = fake_seald({
            let r = reply.clone();
            move |_| r
        });
        let seam = attest_roundtrip(&addr, &nonce(), &ProxyPolicy::default()).unwrap_err();
        assert_eq!(seam, ProxyError::Refused(
            "attest nonce is 0 bytes, expected 32".to_string()
        ));
        assert_eq!(seam.status(), 502);
        // Byte-identical to the original for the same reply.
        let addr2 = fake_seald(move |_| reply.clone());
        same_reason(&seam, original::attest_roundtrip(&addr2, &nonce()).unwrap_err());
    }

    #[test]
    fn a_bad_opcode_maps_like_the_original() {
        let reply = frame(&[0x77, 0x01, 0x02]);
        let addr = fake_seald({
            let r = reply.clone();
            move |_| r
        });
        let seam = attest_roundtrip(&addr, &nonce(), &ProxyPolicy::default()).unwrap_err();
        assert_eq!(seam, ProxyError::BadOpcode(0x77));
        assert_eq!(seam.status(), 502);
        let addr2 = fake_seald(move |_| reply.clone());
        same_reason(&seam, original::attest_roundtrip(&addr2, &nonce()).unwrap_err());
    }

    #[test]
    fn a_refused_frame_size_maps_like_the_original_zero_and_oversize() {
        // declared 0 and declared > max share one reason shape (moved).
        for declared in [0u32, (original::MAX_FRAME + 1) as u32] {
            let reply = declared.to_be_bytes().to_vec();
            let addr = fake_seald({
                let r = reply.clone();
                move |_| r
            });
            let seam = attest_roundtrip(&addr, &nonce(), &ProxyPolicy::default()).unwrap_err();
            assert_eq!(seam, ProxyError::FrameSize(declared as usize));
            assert_eq!(seam.status(), 502);
            let addr2 = fake_seald(move |_| reply.clone());
            same_reason(&seam, original::attest_roundtrip(&addr2, &nonce()).unwrap_err());
        }
    }

    #[test]
    fn a_closed_port_refuses_fast_with_the_moved_reason() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let start = std::time::Instant::now();
        let seam = attest_roundtrip(&addr, &nonce(), &ProxyPolicy::default()).unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(5), "refused returns fast");
        assert!(matches!(seam, ProxyError::Connect(_)));
        assert_eq!(seam.status(), 502);
        let original = original::attest_roundtrip(&addr, &nonce()).unwrap_err();
        same_reason(&seam, original);
    }

    #[test]
    fn a_bad_address_maps_like_the_original() {
        for bad in ["nope", "999.1.1.1:1", "1.2.3.4:notaport", "[::1]:1"] {
            let seam = attest_roundtrip(bad, &nonce(), &ProxyPolicy::default()).unwrap_err();
            assert!(matches!(seam, ProxyError::Addr(_)), "{bad}: {seam:?}");
            assert_eq!(seam.status(), 502);
            let original = original::attest_roundtrip(bad, &nonce()).unwrap_err();
            same_reason(&seam, original);
        }
    }

    #[test]
    fn a_silent_backend_times_out_not_wedges() {
        // A fake that reads the request and then never answers: the read
        // phase must hit the policy bound and classify as Timeout with the
        // moved reason shape `{phase}: {io}`.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_ok() {
                    let n = u32::from_be_bytes(len) as usize;
                    let mut req = vec![0u8; n.min(original::MAX_FRAME)];
                    let _ = stream.read_exact(&mut req);
                    std::thread::sleep(Duration::from_secs(6));
                }
            }
        });
        let policy = ProxyPolicy {
            connect: Duration::from_millis(500),
            read: Duration::from_millis(300),
            write: Duration::from_millis(500),
            max_frame: original::MAX_FRAME,
        };
        let start = std::time::Instant::now();
        let seam = attest_roundtrip(&addr, &nonce(), &policy).unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "the policy bound, not the sleep, bounds the wait: {elapsed:?}"
        );
        let ProxyError::Timeout(reason) = &seam else {
            panic!("expected a Timeout, got {seam:?}");
        };
        assert!(
            reason.starts_with("read response length: ") || reason.starts_with("read response body: "),
            "the phase-labeled reason: {reason}"
        );
        assert_eq!(seam.status(), 502);
    }

    #[test]
    fn an_early_eof_maps_to_short_frame_with_the_moved_reason() {
        // The fake declares a 10-byte body and sends 3, then closes.
        let reply = [0u8, 0, 0, 10, 1, 2, 3].to_vec();
        let addr = fake_seald(move |_| reply);
        let seam = attest_roundtrip(&addr, &nonce(), &ProxyPolicy::default()).unwrap_err();
        assert!(matches!(seam, ProxyError::ShortFrame(_)), "{seam:?}");
        assert_eq!(seam.status(), 502);
        let addr2 = fake_seald(|_| [0u8, 0, 0, 10, 1, 2, 3].to_vec());
        same_reason(&seam, original::attest_roundtrip(&addr2, &nonce()).unwrap_err());
    }

    #[test]
    fn the_nonce_parser_agrees_with_the_original_on_every_shape() {
        let cases = [
            String::new(),
            "abcd".to_string(),
            "ab".repeat(32),
            "AB".repeat(32),
            format!("{}z", "0".repeat(63)),
            format!("{}0", "0".repeat(64)),
            "0".repeat(63),
            "%41".repeat(1) + &"0".repeat(62),
            "00".repeat(31) + "%0",
            "g".repeat(64),
        ];
        for case in cases {
            let seam = parse_hex_nonce(&case);
            let original = original::parse_nonce(&case);
            match (seam, original) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "{case}"),
                (Err(a), Err(b)) => assert_eq!(a, b, "{case}"),
                (seam, original) => panic!("divergence on {case:?}: {seam:?} vs {original:?}"),
            }
        }
        // Mixed case parses to identical bytes (the case-free hex contract).
        assert_eq!(
            parse_hex_nonce(&"AB".repeat(32)).unwrap(),
            parse_hex_nonce(&"ab".repeat(32)).unwrap()
        );
        assert_eq!(parse_hex_nonce(&"ab".repeat(32)).unwrap()[0], 0xab);
    }

    #[test]
    fn a_nonce_error_is_the_only_400_and_the_body_is_the_frozen_shape() {
        let e = ProxyError::Nonce("empty nonce".to_string());
        assert_eq!(e.status(), 400);
        let v: serde_json::Value = serde_json::from_str(&e.json()).unwrap();
        assert_eq!(v["error"], "empty nonce");
    }

    #[test]
    fn the_json_escaping_matches_the_original_byte_for_byte() {
        let nasty = "he said \"no\"\\back\nline\ttab\u{1}end";
        assert_eq!(json_error(nasty), original::json_error(nasty));
        let v: serde_json::Value = serde_json::from_str(&json_error(nasty)).unwrap();
        assert!(v["error"].is_string());
        // The ProxyError path uses the same escaping.
        let e = ProxyError::Refused(nasty.to_string());
        assert_eq!(e.json(), original::json_error(format!("seald refused: {nasty}")));
    }

    #[test]
    fn the_query_parser_matches_the_original_including_prefix_collisions() {
        for (q, k) in [
            ("x=1&nonce=abcd&y=2", "nonce"),
            ("nonce=abcd", "nonce"),
            ("nope=1", "nonce"),
            ("nonceX=1", "nonce"),
            ("nonce=", "nonce"),
        ] {
            assert_eq!(query_param(q, k), original::query_param(q, k), "{q}");
        }
        assert_eq!(query_param("nonce=", "nonce"), Some(""));
    }

    #[test]
    fn utf8_interpretation_uses_the_moved_reason() {
        assert_eq!(utf8_envelope(b"{\"ok\":true}").unwrap(), "{\"ok\":true}");
        let e = utf8_envelope(&[0xff, 0xfe]).unwrap_err();
        assert_eq!(e, ProxyError::NotUtf8);
        assert_eq!(e.status(), 502);
        assert_eq!(e.reason(), "seald returned a non-UTF-8 envelope");
    }
}
