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
//! Transport is chosen by the caller's face, not baked into the frame:
//! [`attest_roundtrip`] is TCP (the loopback admin face a shared-netstack
//! wire owner reaches), and [`attest_roundtrip_uds`] is a Unix-domain socket
//! (the per-daemon-sandbox layout, where the only reachable admin face is a
//! filesystem-permission-gated `admin.sock`, not a TCP port). Both speak the
//! IDENTICAL len-first `[len][opcode][body]` frame with the SAME
//! [`ProxyError`] reason contract; they differ ONLY in how they connect and
//! in the per-face frame cap (the UDS sibling takes it as a parameter, so a
//! face with a tighter contract than the transport default is honored, never
//! silently loosened). Synchronous std-only: no tokio, so an async consumer
//! calls this through `spawn_blocking` without bootproof's proxy core gaining
//! a runtime dependency.

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

/// One `OP_ATTEST` round-trip over a Unix-domain socket: the same frame,
/// the same codec, the same [`ProxyError`] reason contract as
/// [`attest_roundtrip`], connected to `path` instead of a `host:port`. This
/// exists for the per-daemon-sandbox layout, where the admin face is a
/// filesystem-permission-gated `admin.sock` and the TCP default address is
/// the wire owner's own (empty) loopback: a real second consumer, not a
/// speculative seam.
///
/// Two honest asymmetries vs TCP, both deliberate:
///
/// - **No connect timeout.** [`ProxyPolicy::connect`] is unused here, and
///   NOT because a UDS connect "cannot block" (it can: `connect(2)` to a
///   listening SOCK_STREAM whose accept backlog is FULL blocks until a slot
///   frees). The narrower, true reason: TCP's `connect_timeout` exists for
///   the blackholed/filtered-host SYN-retransmit hang (minutes), and that
///   failure mode does not exist on UDS. The realistic UDS connect failures
///   are `ENOENT` (no socket file) and `ECONNREFUSED` (dead listener), both
///   instant. The ONE lingering case, a full accept backlog, means the
///   backend process is up but wedged in accept: a whole-node fault where
///   nothing on the box works anyway, and it is bounded by the CALLER's
///   watchdog (the same seam-thread watchdog that covers every other
///   blocking call into the backend), not by a per-connect knob. A bad or
///   empty path is a [`ProxyError::Connect`] (there is no UDS analog of the
///   TCP address-shape [`ProxyError::Addr`]); the reason shape
///   `connect {target}: {io}` is identical, with `target` = the path.
///
/// - **The frame cap is a parameter, not policy-only.** `max_payload`
///   bounds the declared response length BEFORE allocating the body, capped
///   additionally by [`crate::protocol::MAX_PAYLOAD`] (the transport's hard
///   ceiling), so the effective cap is `min(max_payload, MAX_PAYLOAD)`. A
///   face whose own contract is TIGHTER than the transport default (e.g. a
///   1 MiB page face on a 16 MiB transport default) MUST pass its cap:
///   hardcoding the transport default here would silently LOOSEN the face's
///   DoS bound the moment the face consolidated onto this shared transport.
///   One transport, per-face policy via argument: the mechanism/policy split
///   applied inside the function. The read timeout (`policy.read`) is what
///   turns a declared-but-never-sent oversized frame into a bounded failure
///   (refused at the cap, or `Timeout` on the silent body), so the elapsed
///   bound is the policy, never the peer's whim.
///
/// Every other phase matches TCP exactly: `policy.write` bounds the request
/// write, `policy.read` bounds both response reads, the request frame is the
/// identical len-first `[len][OP_ATTEST][nonce32]`, and the envelope bytes
/// return UNTOUCHED (pass-through).
#[cfg(unix)]
pub fn attest_roundtrip_uds(
    path: &str,
    nonce: &[u8; 32],
    policy: &ProxyPolicy,
    max_payload: usize,
) -> Result<Vec<u8>, ProxyError> {
    // The effective cap: the face's own bound, never above the transport's
    // hard ceiling. Computed BEFORE connect so a nonsense cap is refused
    // without touching the socket.
    let cap = max_payload.min(crate::protocol::MAX_PAYLOAD);
    let mut stream = match std::os::unix::net::UnixStream::connect(path) {
        Ok(s) => s,
        // No is_timeout arm: std gives no connect timeout here and the
        // failure modes above are instant; anything non-OK is a Connect.
        Err(e) => return Err(ProxyError::Connect(format!("connect {path}: {e}"))),
    };
    // SO_RCVTIMEO/SO_SNDTIMEO apply to AF_UNIX stream sockets; a timed-out
    // read_exact then reports TimedOut/WouldBlock, which `is_timeout`
    // already classifies identically to TCP. Set BEFORE the first read so
    // even the `read response length` phase is bounded.
    let _ = stream.set_read_timeout(Some(policy.read));
    let _ = stream.set_write_timeout(Some(policy.write));
    // The request: identical bytes to the TCP path (one codec, two
    // transports): `[4-byte BE len][OP_ATTEST][nonce]`.
    let frame = crate::protocol::encode_len_first(OP_ATTEST, nonce);
    stream
        .write_all(&frame)
        .map_err(|e| ProxyError::WriteFailed(write_reason("write attest request", &e)))?;
    stream
        .flush()
        .map_err(|e| ProxyError::WriteFailed(write_reason("flush attest request", &e)))?;
    // The response frame, classified through the SAME reason shapes as TCP.
    let mut len_prefix = [0u8; 4];
    read_response(&mut stream, &mut len_prefix, "read response length")?;
    let declared = u32::from_be_bytes(len_prefix) as usize;
    if declared == 0 || declared > cap {
        return Err(ProxyError::FrameSize(declared));
    }
    let mut body = vec![0u8; declared];
    read_response(&mut stream, &mut body, "read response body")?;
    // `declared > 0` is guaranteed above, so body[0] exists.
    match body[0] {
        OP_ATTEST => Ok(body[1..].to_vec()),
        OP_ERROR => Err(ProxyError::Refused(String::from_utf8_lossy(&body[1..]).into_owned())),
        other => Err(ProxyError::BadOpcode(other)),
    }
}

/// The UDS sibling's read+classify, generic over the reader so the
/// UnixStream path reuses the moved classification without touching the
/// pinned TCP `read_phase` (which stays typed `&mut TcpStream` so the
/// equivalence gate keeps comparing the seam against the ORIGINAL, not
/// against a shared refactor). Identical reason shapes: timeout →
/// `Timeout`, EOF mid-fill → `ShortFrame`, else `ReadFailed`, each
/// `{phase}: {io}`. The bound is the socket option set by the caller, not a
/// parameter here, exactly as in the TCP path.
#[cfg(unix)]
fn read_response<R: Read>(
    stream: &mut R,
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

    /// The UDS sibling's coverage. The TCP path is the equivalence-gated
    /// one (pinned against wardend's original); this module proves the UDS
    /// transport speaks the SAME frame + reason contract over a
    /// `UnixListener` fake admin face, and enforces the per-face
    /// `max_payload` cap (the mechanism/policy split inside the fn).
    #[cfg(unix)]
    mod uds {
        use super::*;
        use std::os::unix::net::UnixListener;
        use std::path::PathBuf;

        /// A unique socket path under the process temp dir (the crate
        /// convention; no new `tempfile` dep). The `.sock` suffix + pid +
        /// nanos keeps parallel tests from colliding.
        fn uds_path(label: &str) -> PathBuf {
            std::env::temp_dir().join(format!(
                "bootproof-uds-{label}-{}-{}.sock",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
        }

        /// Bind a fake admin face ON THE CALLING THREAD (so the socket file
        /// exists before any client connects), then answer exactly one
        /// request frame with `f(request_payload)`. Returns the path; the
        /// listener is moved into the thread and unlinked on its drop.
        fn fake_uds_admin<F>(label: &str, f: F) -> PathBuf
        where
            F: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
        {
            let path = uds_path(label);
            let listener = UnixListener::bind(&path).unwrap();
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut len = [0u8; 4];
                    if stream.read_exact(&mut len).is_err() {
                        return;
                    }
                    let n = u32::from_be_bytes(len) as usize;
                    if n == 0 || n > crate::protocol::MAX_PAYLOAD {
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
                // `listener` drops here, unlinking the socket file.
            });
            path
        }

        #[test]
        fn a_good_uds_round_trip_returns_the_envelope_bytes_untouched() {
            let envelope = br#"{"bundle":{},"facts":[],"nonce":"ab"}"#.to_vec();
            let mut payload = vec![OP_ATTEST];
            payload.extend_from_slice(&envelope);
            let reply = frame(&payload);
            let path = fake_uds_admin("good", move |_| reply);
            let got =
                attest_roundtrip_uds(path.to_str().unwrap(), &nonce(), &ProxyPolicy::default(), crate::protocol::MAX_PAYLOAD)
                    .unwrap();
            assert_eq!(got, envelope);
        }

        #[test]
        fn the_uds_request_frame_is_len_first_with_the_nonce_verbatim() {
            // The fake echoes the nonce bytes back (skipping its opcode), so
            // the test proves the seam sent `[len=33][OP_ATTEST][nonce32]`
            // and never re-rolled the nonce, identical to TCP.
            let path = fake_uds_admin("req", |req| {
                let mut payload = vec![OP_ATTEST];
                payload.extend_from_slice(&req[1..]);
                frame(&payload)
            });
            let got = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                crate::protocol::MAX_PAYLOAD,
            )
            .unwrap();
            assert_eq!(got, nonce().to_vec());
        }

        #[test]
        fn a_uds_refusal_maps_to_refused_with_the_tcp_reason_shape() {
            let mut payload = vec![OP_ERROR];
            payload.extend_from_slice(b"attest nonce is 0 bytes, expected 32");
            let reply = frame(&payload);
            let path = fake_uds_admin("refused", move |_| reply);
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                crate::protocol::MAX_PAYLOAD,
            )
            .unwrap_err();
            assert_eq!(
                e,
                ProxyError::Refused("attest nonce is 0 bytes, expected 32".to_string())
            );
            assert_eq!(e.reason(), "seald refused: attest nonce is 0 bytes, expected 32");
            assert_eq!(e.status(), 502);
        }

        #[test]
        fn a_uds_bad_opcode_maps_to_bad_opcode() {
            let reply = frame(&[0x77, 0x01, 0x02]);
            let path = fake_uds_admin("opcode", move |_| reply);
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                crate::protocol::MAX_PAYLOAD,
            )
            .unwrap_err();
            assert_eq!(e, ProxyError::BadOpcode(0x77));
            assert_eq!(e.reason(), "unexpected response opcode 119");
            assert_eq!(e.status(), 502);
        }

        #[test]
        fn a_uds_early_eof_maps_to_short_frame() {
            // Declares a 10-byte body, sends 3, closes.
            let reply = [0u8, 0, 0, 10, 1, 2, 3].to_vec();
            let path = fake_uds_admin("eof", move |_| reply);
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                crate::protocol::MAX_PAYLOAD,
            )
            .unwrap_err();
            assert!(matches!(e, ProxyError::ShortFrame(_)), "{e:?}");
            assert_eq!(e.status(), 502);
        }

        #[test]
        fn a_missing_socket_file_is_connect_not_addr_and_fails_fast() {
            // A path that does not exist: ENOENT -> Connect (there is no UDS
            // analog of the TCP Addr shape), and it returns instantly.
            let path = uds_path("missing");
            let start = std::time::Instant::now();
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                crate::protocol::MAX_PAYLOAD,
            )
            .unwrap_err();
            assert!(start.elapsed() < Duration::from_secs(5), "ENOENT is instant");
            assert!(matches!(e, ProxyError::Connect(_)), "{e:?}");
            // The reason shape is the TCP connect-failure shape, target=path.
            assert!(e.reason().starts_with("connect "), "{}", e.reason());
            assert!(e.reason().contains(path.to_str().unwrap()), "{}", e.reason());
            assert_eq!(e.status(), 502);
        }

        #[test]
        fn a_non_socket_path_is_connect() {
            // A path that exists but is NOT a listening socket: connect
            // fails -> Connect (fast). Proves "bad path maps to Connect" for
            // a non-ENOENT failure mode too.
            let path = uds_path("notasocket");
            std::fs::write(&path, b"i am a regular file, not a socket").unwrap();
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                crate::protocol::MAX_PAYLOAD,
            )
            .unwrap_err();
            assert!(matches!(e, ProxyError::Connect(_)), "{e:?}");
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn a_silent_uds_backend_times_out_not_wedges() {
            // Reads the request, then never answers: the READ timeout bounds
            // the wait and classifies as Timeout with the `{phase}: {io}`
            // shape (identical to the TCP timeout test).
            let path = uds_path("silent");
            let listener = UnixListener::bind(&path).unwrap();
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut len = [0u8; 4];
                    if stream.read_exact(&mut len).is_ok() {
                        let n = u32::from_be_bytes(len) as usize;
                        let mut req = vec![0u8; n.min(crate::protocol::MAX_PAYLOAD)];
                        let _ = stream.read_exact(&mut req);
                        std::thread::sleep(Duration::from_secs(6));
                    }
                }
            });
            let policy = ProxyPolicy {
                connect: Duration::from_millis(500), // unused on UDS, documented
                read: Duration::from_millis(300),
                write: Duration::from_millis(500),
                max_frame: DEFAULT_MAX_FRAME,
            };
            let start = std::time::Instant::now();
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &policy,
                crate::protocol::MAX_PAYLOAD,
            )
            .unwrap_err();
            let elapsed = start.elapsed();
            assert!(
                elapsed < Duration::from_secs(5),
                "the read timeout, not the sleep, bounds the wait: {elapsed:?}"
            );
            assert!(matches!(e, ProxyError::Timeout(_)), "{e:?}");
            let r = e.reason();
            assert!(
                r.starts_with("read response length: ") || r.starts_with("read response body: "),
                "the phase-labeled reason: {r}"
            );
            assert_eq!(e.status(), 502);
        }

        #[test]
        fn a_per_face_max_payload_refuses_a_bigger_declared_frame_fast() {
            // THE mandated guard: a face whose contract is 1 MiB passes
            // max_payload = 1<<20. A backend declaring a 2 MiB frame MUST be
            // refused (FrameSize), and FAST: the refusal is on the declared
            // length ONLY, before the body is read or allocated, so even the
            // 60 s default read timeout is never approached. The fake writes
            // just the 4-byte length then closes (it never sends a 2 MiB
            // body); a naive reader would block on the missing body, the
            // cap-first reader refuses immediately.
            let two_mib = 2u32 * 1024 * 1024;
            let reply = two_mib.to_be_bytes().to_vec(); // length prefix only; no body
            let path = fake_uds_admin("bigdeclared", move |_| reply);
            let start = std::time::Instant::now();
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(), // 60 s read timeout, deliberately
                1 << 20,                 // the face's 1 MiB cap
            )
            .unwrap_err();
            let elapsed = start.elapsed();
            assert_eq!(e, ProxyError::FrameSize(two_mib as usize));
            assert!(
                elapsed < Duration::from_secs(10),
                "refused at the cap, never waiting on the read timeout: {elapsed:?}"
            );
            assert_eq!(e.status(), 502);
        }

        #[test]
        fn a_declared_frame_under_the_face_cap_is_accepted() {
            // The companion to the guard: under the SAME 1 MiB face cap, a
            // frame the face accepts (well under 1 MiB) round-trips fine.
            // Together the two prove the cap is honored as a bound, not a
            // blanket reject and not the transport default.
            let envelope = vec![b'x'; 4096];
            let mut payload = vec![OP_ATTEST];
            payload.extend_from_slice(&envelope);
            let reply = frame(&payload);
            let path = fake_uds_admin("undercap", move |_| reply);
            let got = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                1 << 20, // 1 MiB face cap
            )
            .unwrap();
            assert_eq!(got, envelope);
        }

        #[test]
        fn max_payload_above_the_transport_ceiling_is_clamped() {
            // The effective cap is min(max_payload, MAX_PAYLOAD). Ask for a
            // 32 MiB cap (> the 16 MiB transport ceiling); a backend
            // declaring 17 MiB (> 16 MiB but < 32 MiB) must STILL be refused,
            // proving the clamp holds and a caller can never raise the cap
            // above the transport's hard ceiling.
            let declared = 17u32 * 1024 * 1024;
            let reply = declared.to_be_bytes().to_vec();
            let path = fake_uds_admin("clamp", move |_| reply);
            let start = std::time::Instant::now();
            let e = attest_roundtrip_uds(
                path.to_str().unwrap(),
                &nonce(),
                &ProxyPolicy::default(),
                32 * 1024 * 1024, // above MAX_PAYLOAD: must clamp to 16 MiB
            )
            .unwrap_err();
            assert!(start.elapsed() < Duration::from_secs(10), "refused at the clamped cap");
            assert_eq!(e, ProxyError::FrameSize(declared as usize));
        }
    }
}
