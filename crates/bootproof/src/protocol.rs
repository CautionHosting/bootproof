//! `protocol` — the shared wire contract between a network-facing daemon
//! (bootproofd) and the offline hardware owner (enclaved).
//!
//! This is the seam the whole architecture hangs on: the ONLY thing that
//! knows HTTP delegates every hardware request to the ONLY thing that opens
//! `/dev/sev-guest` / `/dev/tpm*`, over a single Unix domain socket. The two
//! ends never share process space, so they share this framing instead.
//!
//! Frame shape (request and response are the SAME shape — byte 0 is an
//! *operation* on the wire from client->server, a *status* on the wire from
//! server->client):
//!
//!     byte 0     : u8  (op on request, status on response)
//!     byte 1..5  : u32 big-endian payload length
//!     byte 5..   : payload (exactly `length` bytes)
//!
//! One request/response per connection is the current convention (the socket
//! is simple and the challenge is the whole request); the framing does not
//! forbid more, but nothing does it yet.
//!
//! No TLS: the socket is loopback, owner-only (0600), and the parent dir is
//! 0700. A corrupt/malicious length prefix is capped at [`MAX_PAYLOAD`].

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Operation: collect signed hardware evidence for one 64-byte challenge.
/// The payload is exactly [`CHALLENGE_LEN`] bytes. Response payload is
/// `serde_json::to_vec(&Vec<Collected>)` (the exact JSON the Bundle carries).
pub const OP_COLLECT: u8 = 0x01;

/// Reserved for a future op (e.g. read PCRs). Declared so the op space is
/// explicit and additive — never repurpose 0x01.
pub const OP_READ_PCRS: u8 = 0x02;

/// The request is a fixed-size 64-byte challenge (front 32 = the client's
/// nonce, back 32 zero; see `channel::challenge_from_nonce`).
pub const CHALLENGE_LEN: usize = 64;

/// Status bytes on the response's byte 0.
pub const RESP_OK: u8 = 0;
pub const RESP_ERR: u8 = 1;

/// Reject any response payload larger than this (a guard against a corrupt
/// length prefix). 16 MiB is far above any real Bundle (a few hundred KB at
/// most).
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Encode a frame: `[tag, u32-BE len, payload]`. `tag` is the op (request) or
/// status (response).
pub fn encode(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a complete in-memory frame into `(tag, payload)`. Enforces the
/// length cap. Used by tests and by any non-async caller.
pub fn decode(buf: &[u8]) -> Result<(u8, Vec<u8>), String> {
    if buf.len() < 5 {
        return Err(format!("frame too short: {} bytes (need >= 5)", buf.len()));
    }
    let tag = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(format!("payload too large: {len} bytes (max {MAX_PAYLOAD})"));
    }
    if buf.len() < 5 + len {
        return Err(format!(
            "frame truncated: have {} bytes, need {}",
            buf.len(),
            5 + len
        ));
    }
    let payload = buf[5..5 + len].to_vec();
    Ok((tag, payload))
}

/// Read exactly `n` bytes, or bail (partial reads on a UDS are rare but we do
/// not want a silent short read to become a garbled frame).
async fn read_exact_ext(stream: &mut (impl AsyncReadExt + Unpin), buf: &mut [u8]) -> Result<(), String> {
    let _ = stream
        .read_exact(buf)
        .await
        .map_err(|e| format!("read failed: {e}"))?;
    Ok(())
}

/// Read one frame off an async stream: `[tag, u32-BE len, payload]`, with the
/// length cap enforced. Returns `(tag, payload)`.
pub async fn read_frame<S>(stream: &mut S) -> Result<(u8, Vec<u8>), String>
where
    S: AsyncReadExt + Unpin,
{
    let mut head = [0u8; 5];
    read_exact_ext(stream, &mut head).await?;
    let tag = head[0];
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(format!("payload too large: {len} bytes (max {MAX_PAYLOAD})"));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_ext(stream, &mut payload).await?;
    }
    Ok((tag, payload))
}

/// Write one frame to an async stream.
pub async fn write_frame<S>(stream: &mut S, tag: u8, payload: &[u8]) -> Result<(), String>
where
    S: AsyncWriteExt + Unpin,
{
    stream
        .write_all(&encode(tag, payload))
        .await
        .map_err(|e| format!("write failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ok() {
        let frame = encode(OP_COLLECT, &[1, 2, 3, 4]);
        let (tag, payload) = decode(&frame).unwrap();
        assert_eq!(tag, OP_COLLECT);
        assert_eq!(payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn round_trip_empty_payload() {
        let frame = encode(RESP_ERR, b"");
        let (tag, payload) = decode(&frame).unwrap();
        assert_eq!(tag, RESP_ERR);
        assert!(payload.is_empty());
    }

    #[test]
    fn header_len_is_be() {
        // A 300-byte payload (0x12C) -> 4-byte BE len 0x00 0x00 0x01 0x2C
        let payload = vec![0xABu8; 300];
        let frame = encode(OP_COLLECT, &payload);
        assert_eq!(&frame[1..5], &[0x00, 0x00, 0x01, 0x2c]);
        let (tag, got) = decode(&frame).unwrap();
        assert_eq!(tag, OP_COLLECT);
        assert_eq!(got.len(), 300);
    }

    #[test]
    fn rejects_short_frame() {
        assert!(decode(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        // header says 10 bytes, only 4 present
        let buf = [0x01u8, 0x00, 0x00, 0x00, 0x0a, 1, 2, 3, 4];
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn rejects_oversized_length_prefix() {
        // claim a 20 MiB payload
        let mut buf = vec![OP_COLLECT];
        buf.extend_from_slice(&((MAX_PAYLOAD + 1) as u32).to_be_bytes());
        buf.push(0);
        assert!(decode(&buf).is_err());
    }

    #[tokio::test]
    async fn async_round_trip() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(4096);
        // a <-> b are two connected endpoints. One task plays the client on
        // `a` (writes the request, reads the response); the other plays the
        // server on `b` (reads the request, writes the response).
        tokio::join!(
            async {
                write_frame(&mut a, OP_COLLECT, &[1, 2, 3]).await.unwrap();
                let (tag, payload) = read_frame(&mut a).await.unwrap();
                assert_eq!(tag, RESP_OK);
                assert_eq!(payload, vec![4, 5]);
            },
            async {
                let (op, payload) = read_frame(&mut b).await.unwrap();
                assert_eq!(op, OP_COLLECT);
                assert_eq!(payload, vec![1, 2, 3]);
                write_frame(&mut b, RESP_OK, &[4, 5]).await.unwrap();
            },
        );
    }

    #[tokio::test]
    async fn async_oversized_rejected() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(4096);
        // header claiming 20 MiB then EOF
        let header = encode(OP_COLLECT, &[]); // 5-byte header, len 0
        let _ = header;
        let mut big = vec![OP_COLLECT];
        big.extend_from_slice(&((MAX_PAYLOAD + 1) as u32).to_be_bytes());
        tokio::spawn(async move {
            let _ = a.write_all(&big).await;
        });
        let r = read_frame(&mut b).await;
        assert!(r.is_err());
    }
}
