//! `bridge` — the file-based transport for the collect protocol.
//!
//! A sandboxed client (gVisor) cannot reach the host-side UDS, so the
//! challenge/response pair is bridged through regular files in a
//! bind-mounted directory instead. The byte contract is frozen (the server
//! side lives in the enclaved daemon); the two ends never share process
//! space, so they share these file names and framing:
//!
//! - `CHALLENGE_FILE` : EXACTLY [`CHALLENGE_LEN`] bytes (the 64-byte
//!   challenge). Written `.tmp` + fsync + atomic rename.
//! - `RESPONSE_FILE`  : the EXACT framed response stream the UDS transport
//!   would have returned (`[status, 4-byte BE len, payload]`, i.e. what
//!   `crate::protocol::write_frame` emits). Written `.tmp` + fsync + atomic
//!   rename; the server deletes the challenge after renaming.
//!
//! The client writes the challenge, then polls for the response every
//! [`DEFAULT_POLL_INTERVAL`]; on find it reads the whole file, DELETES it,
//! and returns the bytes (the framed stream is opaque to the caller — it is
//! parsed with the SAME `read_frame` path the UDS transport uses). A stale
//! response from a crashed round is deleted before a new challenge is
//! written (the server guarantees order; this is defensive only).

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

/// Challenge file name (relative to the bridge dir).
pub const CHALLENGE_FILE: &str = "evidence.challenge";
/// Response file name (relative to the bridge dir).
pub const RESPONSE_FILE: &str = "evidence.response";
/// The `.tmp` suffix used for the write-then-rename atomic handoff.
pub const TMP_SUFFIX: &str = ".tmp";

/// The challenge is the same fixed-size 64 bytes as the UDS request.
pub const CHALLENGE_LEN: usize = crate::protocol::CHALLENGE_LEN;

/// Client poll interval while waiting for the response file (500 ms).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Default response timeout (10 s).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Write the 64-byte challenge: `<name>.tmp` -> fsync -> atomic rename to
/// `<name>`. The final file holds EXACTLY `CHALLENGE_LEN` bytes and nothing
/// else ever sees a partial write (the rename is atomic on a single
/// filesystem).
///
/// Also deletes a stale `RESPONSE_FILE` first (a crashed round may leave
/// one; the server guarantees order, this is defensive).
pub fn write_challenge(dir: &Path, challenge: &[u8; CHALLENGE_LEN]) -> io::Result<()> {
    let stale = dir.join(RESPONSE_FILE);
    match fs::remove_file(&stale) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    atomic_write_file(dir, CHALLENGE_FILE, challenge)
}

/// Read the whole response file and DELETE it. Returns the exact framed
/// stream bytes (`[status, 4-byte BE len, payload]`) — opaque here, parsed
/// by the caller with `crate::protocol::read_frame` exactly as the UDS path
/// does.
pub fn read_response(dir: &Path) -> io::Result<Vec<u8>> {
    let path = dir.join(RESPONSE_FILE);
    let buf = fs::read(&path)?;
    let _ = fs::remove_file(&path);
    Ok(buf)
}

/// The client side of one bridge round trip: clean any stale response,
/// write the challenge, poll for the response every `poll_interval` until
/// `timeout`, then return the framed response bytes (read + deleted).
///
/// `poll_interval` and `timeout` are injected (defaults [`DEFAULT_POLL_INTERVAL`]
/// / [`DEFAULT_TIMEOUT`]) so tests can run with zero/near-zero waits.
pub async fn collect_via_bridge(
    dir: &Path,
    challenge: &[u8; CHALLENGE_LEN],
    poll_interval: Duration,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    write_challenge(dir, challenge)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match read_response(dir) {
            Ok(buf) => return Ok(buf),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(timeout_err(timeout));
        }
        // Never sleep past the deadline, even on a coarse poll interval.
        let wait = poll_interval.min(deadline - now);
        if wait.is_zero() {
            // Injected zero interval (tests): yield the executor without a
            // busy spin. A zero sleep is a scheduler yield (tokio `time`,
            // no `task` feature needed).
            tokio::time::sleep(Duration::ZERO).await;
        } else {
            tokio::time::sleep(wait).await;
        }
    }
}

fn timeout_err(timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("evidence bridge: no response within {}s", timeout.as_secs()),
    )
}

/// Write `contents` to `dir/name` atomically: `dir/name.tmp` -> fsync ->
/// rename to `dir/name`, then fsync the directory entry.
fn atomic_write_file(dir: &Path, name: &str, contents: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}{TMP_SUFFIX}"));
    let final_ = dir.join(name);
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &final_)?;
    // Persist the directory entry (best-effort: not every fs supports it).
    let _ = fs::File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A unique temp dir for one test; removed by the caller.
    fn tempdir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bootproof-bridge-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fake bridge server: poll for the challenge, reply with a known
    /// framed response, delete the challenge — the exact server contract.
    /// Takes ownership of its inputs so it can be spawned 'static.
    async fn fake_server(dir: PathBuf, expected: [u8; CHALLENGE_LEN], payload: Vec<u8>) {
        let challenge = dir.join(CHALLENGE_FILE);
        let response = dir.join(RESPONSE_FILE);
        let mut saw = false;
        while !saw {
            if let Ok(c) = fs::read(&challenge) {
                if c.len() == CHALLENGE_LEN && c.as_slice() == &expected[..] {
                    let mut frame = Vec::with_capacity(5 + payload.len());
                    frame.push(crate::protocol::RESP_OK);
                    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                    frame.extend_from_slice(&payload);
                    let _ = fs::remove_file(&response);
                    let _ = super::atomic_write_file(&dir, RESPONSE_FILE, &frame);
                    let _ = fs::remove_file(&challenge);
                    saw = true;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn write_challenge_is_atomic_and_exactly_64_bytes() {
        let dir = tempdir("atomic");
        let c: [u8; CHALLENGE_LEN] = [0x7Eu8; CHALLENGE_LEN];
        write_challenge(&dir, &c).unwrap();

        // The final file exists with EXACTLY the challenge bytes.
        assert_eq!(fs::read(dir.join(CHALLENGE_FILE)).unwrap(), c);
        // No .tmp artifact survives the rename.
        assert!(!dir.join(format!("{CHALLENGE_FILE}{TMP_SUFFIX}")).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_response_returns_bytes_and_deletes_file() {
        let dir = tempdir("read");
        let frame = crate::protocol::encode(crate::protocol::RESP_OK, b"evidence");
        fs::write(dir.join(RESPONSE_FILE), &frame).unwrap();

        let got = read_response(&dir).unwrap();
        assert_eq!(got, frame, "returns the exact framed bytes, unparsed");
        assert!(!dir.join(RESPONSE_FILE).exists(), "file is deleted after read");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_response_is_cleaned_before_challenge_write() {
        let dir = tempdir("stale");
        // A crashed round left a response behind.
        fs::write(dir.join(RESPONSE_FILE), b"stale").unwrap();

        let c: [u8; CHALLENGE_LEN] = [0x11u8; CHALLENGE_LEN];
        write_challenge(&dir, &c).unwrap();

        assert!(!dir.join(RESPONSE_FILE).exists(), "stale response removed");
        assert_eq!(fs::read(dir.join(CHALLENGE_FILE)).unwrap(), c);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn timeout_fires_without_a_server() {
        let dir = tempdir("timeout");
        let c: [u8; CHALLENGE_LEN] = [0x22u8; CHALLENGE_LEN];

        let err = collect_via_bridge(&dir, &c, Duration::from_millis(10), Duration::from_millis(50))
            .await
            .err()
            .expect("no server => timeout");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let msg = err.to_string();
        assert!(
            msg.starts_with("evidence bridge: no response within"),
            "error names the bridge and the timeout: {msg}"
        );
        // The challenge was still written (a server could pick it up later).
        assert!(dir.join(CHALLENGE_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn round_trip_against_fake_server_bytes_match() {
        let dir = tempdir("roundtrip");
        let c: [u8; CHALLENGE_LEN] = [0x33u8; CHALLENGE_LEN];
        let payload: Vec<u8> = (0..100u16).map(|i| i as u8).collect();
        let expected_frame = crate::protocol::encode(crate::protocol::RESP_OK, &payload);

        let _server = tokio::spawn(fake_server(dir.clone(), c, payload.clone()));
        let got = collect_via_bridge(&dir, &c, Duration::from_millis(20), Duration::from_secs(5))
            .await
            .expect("round trip completes");

        assert_eq!(got, expected_frame, "framed bytes match the UDS stream");
        // Both files are consumed: response deleted by the client, challenge
        // deleted by the server.
        assert!(!dir.join(RESPONSE_FILE).exists());
        assert!(!dir.join(CHALLENGE_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn zero_poll_interval_terminates() {
        // Injected Duration::ZERO poll must not spin forever: it re-checks
        // the deadline and times out.
        let dir = tempdir("zeropoll");
        let c: [u8; CHALLENGE_LEN] = [0x44u8; CHALLENGE_LEN];
        let err = collect_via_bridge(&dir, &c, Duration::ZERO, Duration::from_millis(20))
            .await
            .err()
            .expect("zero poll still times out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        std::fs::remove_dir_all(&dir).ok();
    }
}
