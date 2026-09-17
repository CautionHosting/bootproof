//! Integration proof of the restructured bootproofd: it is a thin CLI over
//! `bootproof::attest::run`, and `run` routes every /attestation challenge
//! to the enclaved evidence daemon's Unix socket.
//!
//! Test: spawn `bootproof::collect::serve` on a temp-dir UDS with a mock
//! channel (deterministic evidence), run the FULL `bootproof::attest::run`
//! on a random localhost port pointed at that UDS, POST /attestation over
//! TLS with a 32-byte nonce, and assert the returned Bundle's evidence
//! carries the mock channel's name and the nonce echoes. A second case
//! points run() at a bogus socket: the honest boundary (NOT PROVEN) must
//! still return a 200 Bundle with NO evidence, never a crash or 500.
//!
//! The TLS client accepts any certificate: the node self-signs its ECDSA
//! P-384 identity into the state dir at startup.

use base64::Engine as _;
use std::collections::BTreeMap;
use std::sync::Arc;

use bootproof::channel::{Channel, Collected};
use bootproof::wire::Evidence;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use tokio::io::AsyncWriteExt;

/// Deterministic mock channel (mirrors MockCh in the lib's attest tests).
struct MockCh;
impl Channel for MockCh {
    fn name(&self) -> &'static str {
        "mockch"
    }
    fn detect(&self) -> bool {
        true
    }
    fn collect(&self, nonce: &[u8; 64], _od: &[Vec<u8>]) -> Result<Collected, String> {
        let mut doc = Vec::new();
        doc.extend_from_slice(b"mock-doc:");
        doc.extend_from_slice(&nonce[..8]);
        Ok(Collected {
            evidence: Evidence {
                channel: "mockch".into(),
                doc: bootproof::b64::B64::new(doc),
                anchors: BTreeMap::new(),
            },
            keys: None,
        })
    }
}

/// Accept-any verifier: the node self-signs its ECDSA P-384 identity at
/// startup, so the test client skips chain validation.
#[derive(Debug)]
struct AcceptAny;
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP384_SHA384]
    }
}

fn tls_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth()
}

/// POST /attestation with the given 32-byte nonce; return (status, body).
#[allow(unused_assignments)] // last_err is read only in the panic path
async fn post_attestation(
    host: &str,
    nonce: &[u8; 32],
) -> (String, Vec<u8>) {
    let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
    let body = format!("{{\"nonce\":\"{b64}\"}}");
    let request = format!(
        "POST /attestation HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    // The ServerName must be the bare IP (no port): rustls rejects
    // "ip:port" strings.
    let ip = host.rsplit_once(':').map(|(i, _)| i.to_string()).unwrap_or_else(|| host.to_string());
    let server_name = ServerName::try_from(ip).expect("host is an IP literal");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut last_err = String::from("no attempt");
    loop {
        match tokio::net::TcpStream::connect(host).await {
            Ok(stream) => {
                match tokio_rustls::TlsConnector::from(Arc::new(tls_client_config()))
                    .connect(server_name.clone(), stream)
                    .await
                {
                    Ok(mut conn) => {
                        match conn.write_all(request.as_bytes()).await {
                            Ok(()) => return read_response(conn).await,
                            Err(e) => last_err = format!("write: {e}"),
                        }
                    }
                    Err(e) => last_err = format!("tls: {e}"),
                }
            }
            Err(e) => last_err = format!("tcp: {e}"),
        }
        if std::time::Instant::now() > deadline {
            panic!("no /attestation response: {last_err}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Read the whole HTTP/1.1 response (Connection: close) and split it into
/// (status line, body bytes).
async fn read_response(
    mut conn: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut conn, &mut buf)
        .await
        .expect("read response");
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let status = head.lines().next().expect("status line").to_string();
    (status, buf[head_end + 4..].to_vec())
}

async fn run_case(
    name: &str,
    collect_socket: std::path::PathBuf,
    with_daemon: bool,
) -> (String, Vec<u8>) {
    let nonce = [0x5Au8; 32];
    let dir = std::env::temp_dir().join(format!(
        "bootproofd-it-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("state")).expect("state dir");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let host = listener.local_addr().unwrap().to_string();
    drop(listener); // run() re-binds this address

    let handle = tokio::spawn({
        let socket = collect_socket.clone();
        let listen = host.clone();
        let state = dir.join("state");
        async move {
            bootproof::attest::run(bootproof::attest::Opts {
                listen,
                state,
                key: None,
                metadata: None,
                collect_socket: socket,
            })
            .await
        }
    });

    // If the daemon case: wait for the UDS to appear (serve creates it).
    if with_daemon {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !collect_socket.exists() {
            if std::time::Instant::now() > deadline {
                handle.abort();
                panic!("collect socket never appeared");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // post_attestation retries connects for 15s: run() self-signs the
    // identity before it reaches the accept loop, so the first connect may
    // fail.
    let (status, body) = post_attestation(&host, &nonce).await;

    handle.abort();
    std::fs::remove_dir_all(&dir).ok();

    (status, body)
}

#[tokio::test]
async fn attestation_routes_through_collect_socket() {
    let dir = std::env::temp_dir().join(format!(
        "bootproofd-it-daemon-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("daemon dir");
    let sock = dir.join("evid.sock");
    let _ = std::fs::remove_file(&sock);

    let ch: Arc<Vec<Box<dyn Channel + Send + Sync>>> =
        Arc::new(vec![Box::new(MockCh) as Box<dyn Channel + Send + Sync>]);
    let daemon = tokio::spawn(bootproof::collect::serve(sock.clone(), ch));

    let (status, body) = run_case("up", sock, true).await;
    daemon.abort();
    std::fs::remove_dir_all(&dir).ok();

    let body = String::from_utf8_lossy(&body).to_string();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected 200, got: {status}\nbody: {body}"
    );

    let bundle: serde_json::Value =
        serde_json::from_str(&body).expect("bundle is JSON");
    assert_eq!(bundle["evidence"].as_array().unwrap().len(), 1, "body: {body}");
    let ev = &bundle["evidence"][0];
    assert_eq!(
        ev["channel"].as_str(),
        Some("mockch"),
        "evidence must come from the mock channel over the UDS; body: {body}"
    );
    // doc = b"mock-doc:" + first 8 bytes of the 64-byte challenge (== nonce).
    let doc_b64 = ev["doc"].as_str().expect("doc is b64");
    let doc = base64::engine::general_purpose::STANDARD
        .decode(doc_b64)
        .expect("doc decodes");
    assert_eq!(&doc[..9], b"mock-doc:");
    assert_eq!(
        &doc[9..],
        &[0x5Au8; 8],
        "doc must bind the challenge nonce (front 8 of the 64-byte expansion)"
    );
    // Nonce echo: the Bundle's nonce is the client's 32-byte nonce.
    let nonce_b64 = bundle["nonce"].as_str().expect("nonce is b64");
    let echoed = base64::engine::general_purpose::STANDARD
        .decode(nonce_b64)
        .expect("nonce decodes");
    assert_eq!(echoed, [0x5Au8; 32], "Bundle nonce must echo the client nonce");
}

#[tokio::test]
async fn daemon_down_degrades_to_not_proven_not_a_crash() {
    // A socket path nothing is listening on: the honest boundary is a 200
    // Bundle with NO hardware evidence, never a 500 or a crashed node.
    let bogus = std::path::PathBuf::from("/nonexistent/bootproofd-it/nope.sock");
    let (status, body) = run_case("down", bogus, false).await;
    let body = String::from_utf8_lossy(&body).to_string();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "honest boundary must still be 200, got: {status}\nbody: {body}"
    );
    let bundle: serde_json::Value = serde_json::from_str(&body).expect("bundle is JSON");
    assert!(
        bundle["evidence"].as_array().unwrap().is_empty(),
        "daemon down => NO hardware evidence (NOT PROVEN); body: {body}"
    );
}
