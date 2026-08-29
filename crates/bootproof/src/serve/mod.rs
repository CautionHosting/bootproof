//! `bootproof serve` — a self-contained NitroTPM attestation service.
//!
//! Serves a small plain-HTTP API against a single TPM (char device, or a
//! tpm-bridge over TCP):
//!
//! - `POST /attest` `{ nonce?, user_data?, public_key? }` -> the attestation
//!   chain: the nonce echoed, the parsed fields (module id, PCRs, timestamp),
//!   the raw COSE_Sign1 document (base64), and the certificate chain
//!   (leaf first, then the CA bundle), verifiable against the AWS Nitro
//!   roots of trust.
//! - `GET  /health` -> liveness.
//!
//! The TPM is a single sequential device, so all requests are serialized
//! through one `Mutex<Tpm>`; the (blocking, multi-second) NSM vendor
//! command runs on the blocking-thread pool.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use bootproof_tpm::attest::parse_attestation_document;
use bootproof_tpm::Tpm;
use serde::Deserialize;
use tower_service::Service;

use crate::facts::Facts;

/// Options for `bootproof serve`.
pub struct Opts {
    /// Address to listen on (plain HTTP, default `127.0.0.1:8443`).
    pub listen: String,
    /// An already-opened, started TPM connection.
    pub tpm: Tpm,
    /// Raw NV index of the persistent NSM scratch buffer.
    pub nv_index: u32,
}

/// Shared per-request state.
struct App {
    tpm: Arc<Mutex<Tpm>>,
    nv_index: u32,
}

#[derive(Deserialize)]
struct AttestRequest {
    /// Caller nonce (hex or base64). If absent, the server generates 32
    /// random bytes from the TPM and echoes them.
    nonce: Option<String>,
    /// Extra user data to echo (hex or base64).
    user_data: Option<String>,
    /// A client public key (base64 PEM/DER) to include in the document.
    public_key: Option<String>,
}

#[derive(serde::Serialize)]
struct AttestResponse {
    /// The nonce bound into the document (hex).
    nonce: String,
    /// Module identity, e.g. `i-...-tpm0000000000000000`.
    module_id: String,
    /// PCR digest algorithm name, e.g. `SHA384`.
    digest: String,
    /// Document timestamp in milliseconds since the Unix epoch.
    timestamp_ms: u64,
    /// PCR register values keyed by index (hex strings).
    pcrs: BTreeMap<String, String>,
    /// The raw COSE_Sign1 attestation document (base64).
    document: String,
    /// The certificate chain (base64 DER): leaf first, then the CA bundle.
    chain: Vec<String>,
    /// Local, self-reported system facts (CPU, OS, kernel, disks, TPM vendor,
    /// SEV-SNP presence). Supporting context; the signed doc is authoritative.
    facts: Facts,
}

async fn health() -> &'static str {
    "ok"
}

/// Encode bytes as lowercase hex.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode a hex or base64 string into bytes (hex wins on even-length input).
fn decode_hex_or_b64(s: &str) -> anyhow::Result<Vec<u8>> {
    let t = s.trim();
    if !t.is_empty() && t.len() % 2 == 0 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        let b = (0..t.len() / 2)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        return Ok(b);
    }
    Ok(base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|e| anyhow::anyhow!("base64: {e}"))?)
}

async fn attest(
    State(app): State<Arc<App>>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, (StatusCode, String)> {
    let user_data = req
        .user_data
        .as_deref()
        .map(decode_hex_or_b64)
        .transpose()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("user_data: {e}")))?;
    let public_key = req
        .public_key
        .as_deref()
        .map(|s| base64::engine::general_purpose::STANDARD.decode(s.trim()))
        .transpose()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("public_key: {e}")))?;
    let nonce = match req.nonce.as_deref() {
        Some(s) => Some(
            decode_hex_or_b64(s)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("nonce: {e}")))?,
        ),
        None => None,
    };

    let nv_index = app.nv_index;
    let tpm = app.tpm.clone();
    let (nonce, document, facts, sysfacts) =
        tokio::task::spawn_blocking(
            move || -> anyhow::Result<(Vec<u8>, Vec<u8>, bootproof_tpm::attest::AttestationFacts, Facts)> {
                let mut tpm =
                    tpm.lock().map_err(|e| anyhow::anyhow!("tpm mutex poisoned: {e}"))?;
                let nonce = match nonce {
                    Some(n) => n,
                    None => tpm.get_random(32)?,
                };
                let document =
                    tpm.attestation_document(user_data, Some(nonce.clone()), public_key, nv_index)?;
                let facts = parse_attestation_document(&document)?;
                let sysfacts = Facts::collect(Some(&mut *tpm));
                Ok((nonce, document, facts, sysfacts))
            },
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let pcrs: BTreeMap<String, String> = facts
        .pcrs
        .iter()
        .map(|(k, v)| (k.to_string(), hex(v)))
        .collect();
    let chain: Vec<String> = std::iter::once(facts.certificate.clone())
        .chain(facts.cabundle.iter().cloned())
        .map(|c| base64::engine::general_purpose::STANDARD.encode(&c))
        .collect();

    Ok(Json(AttestResponse {
        nonce: hex(&nonce),
        module_id: facts.module_id,
        digest: facts.digest,
        timestamp_ms: facts.timestamp_ms,
        pcrs,
        document: base64::engine::general_purpose::STANDARD.encode(&document),
        chain,
        facts: sysfacts,
    }))
}

/// Run the serve loop.
pub async fn run(opts: Opts) -> anyhow::Result<()> {
    let app = Arc::new(App {
        tpm: Arc::new(Mutex::new(opts.tpm)),
        nv_index: opts.nv_index,
    });

    let router = axum::Router::new()
        .route("/health", get(health))
        .route("/attest", post(attest))
        .with_state(app.clone());

    let listener = tokio::net::TcpListener::bind(&opts.listen).await?;
    eprintln!("[serve] listening on {} (nv index {:#010x})", opts.listen, opts.nv_index);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let peer = peer.to_string();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = hyper_util::rt::TokioIo::new(tcp);
            let service = hyper::service::service_fn(move |request| {
                let mut router = router.clone();
                async move { router.call(request).await }
            });
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(stream, service)
            .await
            {
                eprintln!("[serve] conn {peer}: {e}");
            }
        });
    }
}
