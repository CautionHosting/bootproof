//! The `collect` daemon: the SOLE process that touches the attestation
//! hardware (`/dev/tpm0`, `/dev/sev-guest`). It listens on a Unix domain
//! socket and, for each connection, collects the node's signed evidence for
//! one 64-byte challenge and hands the result back over the socket.
//!
//! Why it exists: the `attest` node (and later the sshdt bridge) run
//! sandboxed under gVisor, which forbids raw device reads. The hardware
//! stays host-side in this daemon; the sandboxed node talks to it over a
//! plain UDS (no TLS: loopback, owner-only socket). The daemon owns the
//! channel registration (built once by `attest::build_channels`) and runs the
//! SAME `channel::collect_all` the `attest` in-process fallback uses, so the
//! two paths can never drift on ordering or the slot-link fold.
//!
//! Wire format (one request per connection):
//!   request : exactly 64 bytes = the challenge `C` (front 32 == the client's
//!             32-byte nonce, back 32 zero; see `channel::challenge_from_nonce`)
//!   response: 1 status byte, 4-byte big-endian payload length, payload
//!             status 0 (OK)  -> serde_json of `Vec<Collected>`
//!             status 1 (ERR) -> UTF-8 error message
//!
//! The `Collected` entries ride as the exact same JSON the Bundle carries, so
//! the sandboxed node can splice them straight into its `Bundle` evidence.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use crate::channel::{collect_all, Channel, Collected};

/// Default socket path. `/run` is a boot-cleared tmpfs; the daemon creates the
/// directory if it is absent. Overridable via `--socket`.
pub const DEFAULT_SOCKET: &str = "/run/bootproof/collect.sock";

/// The request is a fixed-size 64-byte challenge.
pub const CHALLENGE_LEN: usize = 64;

/// Response status bytes.
pub const RESP_OK: u8 = 0;
pub const RESP_ERR: u8 = 1;

/// Reject any daemon response payload larger than this (a defense against a
/// corrupt/malicious length prefix on the socket). 16 MiB is far above any
/// real Bundle (a few hundred KB at most).
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Collect daemon: bind the UDS and serve one request per connection, forever.
///
/// `channels` is the shared registration (the SOLE device registration on the
/// host). The daemon never reads a device directly; it delegates each
/// challenge to `channel::collect_all`, which runs the channels in the
/// slot-link order (non-tpm2 first, tpm2 last with the other docs folded into
/// the slot link).
pub async fn serve(
    socket: PathBuf,
    channels: Arc<Vec<Box<dyn Channel + Send + Sync>>>,
) -> anyhow::Result<()> {
    let socket: &Path = &socket;
    // Make the parent dir (e.g. /run/bootproof) if it is absent, and clear a
    // stale socket from a previous run.
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(socket);

    let listener = tokio::net::UnixListener::bind(socket)?;
    // Owner-only: the collect daemon is the hardware boundary. The sandboxed
    // node runs as the same owner (the operator manages ownership/mode).
    let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600));

    info!(socket = %socket.display(), "collect: listening (sole device toucher)");
    loop {
        let (stream, _peer) = listener.accept().await?;
        let channels = channels.clone();
        tokio::spawn(async move {
            let _ = handle_conn(stream, channels).await;
        });
    }
}

/// Handle one connection: read one 64-byte challenge, collect, write the
/// response frame, then close (one request per connection).
async fn handle_conn(
    mut stream: tokio::net::UnixStream,
    channels: Arc<Vec<Box<dyn Channel + Send + Sync>>>,
) {
    let mut challenge = [0u8; CHALLENGE_LEN];
    if let Err(e) = stream.read_exact(&mut challenge).await {
        debug!(%e, "collect: read challenge failed");
        return;
    }

    // Collect off the async executor: the channels read devices (blocking I/O).
    let result = tokio::task::spawn_blocking({
        let channels = channels.clone();
        move || collect_all(&channels, &challenge)
    })
    .await;

    let (status, payload): (u8, Vec<u8>) = match result {
        Ok(Ok(collected)) => (
            RESP_OK,
            serde_json::to_vec(&collected).unwrap_or_default(),
        ),
        Ok(Err(e)) => (RESP_ERR, e.into_bytes()),
        Err(e) => (RESP_ERR, e.to_string().into_bytes()),
    };

    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(status);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    if let Err(e) = stream.write_all(&frame).await {
        debug!(%e, "collect: write response failed");
    }
}

/// Client: connect to the collect daemon, send one 64-byte challenge, and
/// receive the collected evidence. Single attempt (a connect failure means the
/// daemon is not up; the caller — the `attest` node — decides whether to fall
/// back to the in-process path).
pub async fn request(socket: &Path, challenge: &[u8; CHALLENGE_LEN]) -> anyhow::Result<Vec<Collected>> {
    let mut stream = tokio::net::UnixStream::connect(socket).await?;

    // Request: the raw 64-byte challenge.
    stream.write_all(challenge).await?;

    // Response: status byte + 4-byte BE length + payload.
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_PAYLOAD {
        anyhow::bail!("collect daemon payload too large: {n} bytes");
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;

    match status[0] {
        RESP_OK => Ok(serde_json::from_slice(&buf)?),
        RESP_ERR => {
            let msg = String::from_utf8_lossy(&buf);
            anyhow::bail!("collect daemon error: {msg}")
        }
        other => anyhow::bail!("collect daemon unknown status byte: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use crate::channel::challenge_from_nonce;
    use crate::wire::{B64, Evidence};

    /// Deterministic mock channel. Records, in a shared order log, the
    /// `other_docs` it was given so the slot-link ordering can be asserted.
    struct Mock {
        name: &'static str,
        detect: bool,
        doc: Vec<u8>,
        order: Arc<Order>,
    }

    #[derive(Default)]
    struct Order {
        calls: Mutex<Vec<(String, Vec<Vec<u8>>)>>,
    }

    impl Channel for Mock {
        fn name(&self) -> &'static str {
            self.name
        }
        fn detect(&self) -> bool {
            self.detect
        }
        fn collect(&self, nonce: &[u8; 64], other_docs: &[Vec<u8>]) -> Result<Collected, String> {
            let _ = nonce;
            self.order
                .calls
                .lock()
                .unwrap()
                .push((self.name.to_string(), other_docs.to_vec()));
            Ok(Collected {
                evidence: Evidence {
                    channel: self.name.to_string(),
                    doc: B64::new(self.doc.clone()),
                    anchors: BTreeMap::new(),
                },
                keys: None,
            })
        }
    }

    fn channels() -> (Arc<Vec<Box<dyn Channel + Send + Sync>>>, Arc<Order>) {
        let order = Arc::new(Order::default());
        let snp = Mock {
            name: "snp",
            detect: true,
            doc: b"snp-doc".to_vec(),
            order: order.clone(),
        };
        let tpm2 = Mock {
            name: "tpm2",
            detect: true,
            doc: b"tpm2-doc".to_vec(),
            order: order.clone(),
        };
        // An absent channel: must degrade (be skipped), never fail.
        let aws = Mock {
            name: "aws-cp",
            detect: false,
            doc: b"aws-doc".to_vec(),
            order: order.clone(),
        };
        let v: Vec<Box<dyn Channel + Send + Sync>> = vec![Box::new(aws), Box::new(snp), Box::new(tpm2)];
        (Arc::new(v), order)
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn challenge_front32_is_nonce_back32_zero() {
        let n = [0xABu8; 32];
        let c = challenge_from_nonce(&n);
        assert_eq!(&c[..32], &n[..]);
        assert!(c[32..].iter().all(|b| *b == 0));
    }

    #[test]
    fn collect_all_orders_snp_first_tpm2_last_with_fold() {
        let (ch, order) = channels();
        let c = challenge_from_nonce(&[7u8; 32]);
        let out = collect_all(&ch, &c).unwrap();

        // The absent channel degraded; snp first, tpm2 last.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].evidence.channel, "snp");
        assert_eq!(out[1].evidence.channel, "tpm2");

        // Slot-link order: snp saw no other docs; tpm2 saw [snp doc] so it can
        // fold the other channel's doc into PCR22 before quoting.
        let calls = order.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "snp");
        assert!(calls[0].1.is_empty());
        assert_eq!(calls[1].0, "tpm2");
        assert_eq!(calls[1].1, vec![b"snp-doc".to_vec()]);
    }

    #[test]
    fn response_frame_roundtrip() {
        // What the daemon writes for an OK response.
        let payload = serde_json::to_vec(&[Collected {
            evidence: Evidence {
                channel: "snp".into(),
                doc: B64::new(b"x".to_vec()),
                anchors: BTreeMap::new(),
            },
            keys: None,
        }])
        .unwrap();
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(RESP_OK);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        // Parse it back the way `request()` does.
        assert_eq!(frame[0], RESP_OK);
        let n = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(n, payload.len());
        let back: Vec<Collected> = serde_json::from_slice(&frame[5..]).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].evidence.channel, "snp");
        assert_eq!(&back[0].evidence.doc.0[..], b"x");
    }

    #[test]
    fn daemon_client_roundtrip_over_udspath() {
        let dir = std::env::temp_dir().join(format!(
            "bootproof-collect-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("collect.sock");
        let _ = std::fs::remove_file(&sock);

        let (ch, _order) = channels();
        let c = challenge_from_nonce(&[0x42u8; 32]);

        let out = block_on(async move {
            let daemon = tokio::spawn(serve(sock.clone(), ch));
            // Wait for the socket file to appear (bind happens at serve start).
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !sock.exists() {
                if std::time::Instant::now() > deadline {
                    daemon.abort();
                    return Err(anyhow::anyhow!("socket never appeared"));
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let res = request(&sock, &c).await;
            daemon.abort();
            res
        });

        std::fs::remove_dir_all(&dir).ok();

        let out = out.unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].evidence.channel, "snp");
        assert_eq!(out[1].evidence.channel, "tpm2");
        assert_eq!(&out[0].evidence.doc.0[..], b"snp-doc");
        assert_eq!(&out[1].evidence.doc.0[..], b"tpm2-doc");
    }
}
