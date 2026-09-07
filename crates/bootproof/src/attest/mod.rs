//! `bootproof attest` — the node server.
//!
//! Loads (or generates) an ECDSA P-384 TLS identity, detects the active
//! channels, and serves the attestation API over TLS:
//!
//! - `POST /attestation` `{ nonce? }` -> the Bundle
//! - `GET  /info`      -> node id, platform, channels, daemon pin
//! - `GET  /health`    -> liveness
//!
//! The server is stateless per request: nonce in, Bundle out. The only
//! persistent state is the TLS identity key.

use std::path::Path;
use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE, Method},
    routing::get,
    routing::post,
};
use tower_service::Service;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};

use crate::channel::{Channel, Collected};
use crate::spki::pin_of_cert;
use crate::wire::{B64, Bundle, Info, BUNDLE_V};

pub mod snp;
pub mod tpm2;

pub const DEFAULT_LISTEN: &str = "0.0.0.0:443";
pub const DEFAULT_STATE: &str = "/var/lib/bootproof";

/// Options for `bootproof attest`.
pub struct Opts {
    pub listen: String,
    pub state: std::path::PathBuf,
    /// Static TLS key (PEM PKCS8 P-384). If set, used in place of the
    /// state-dir identity (for reproducible images).
    pub key: Option<std::path::PathBuf>,
    /// Optional metadata JSON file.
    pub metadata: Option<std::path::PathBuf>,
    /// swtpm over TCP (host:port). Overrides char-device detection.
    pub tcp: Option<String>,
}

/// Install the ring crypto provider as the rustls default.
pub fn install_crypto_provider() {
    use rustls::crypto::CryptoProvider;
    let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// The node's TLS identity: an ECDSA P-384 keypair + self-signed cert.
pub struct Identity {
    /// Raw P-384 secret scalar (48 bytes).
    secret: [u8; 48],
    /// Self-signed X.509 cert (DER).
    cert_der: Vec<u8>,
    /// The SPKI pin: hex `SHA-256(SPKI DER)`.
    pin: String,
}

impl Identity {
    /// Load the identity from `state`, generating + persisting it on first
    /// run. If `key_pem` is set, load that key instead (pairing it with the
    /// stored cert, or generating a fresh self-signed one).
    pub fn load_or_generate(
        state: &Path,
        node_id: &str,
        key_pem: Option<&Path>,
    ) -> anyhow::Result<Self> {
        install_crypto_provider();
        let key_path = state.join("identity.pk8");
        let cert_path = state.join("identity.crt");

        let (secret, cert_der) = match key_pem {
            Some(pem) => {
                let der = load_pkcs8_pem(pem)?;
                let secret = scalar_from_pkcs8(&der)?;
                let cert_der = match read_if_exists(&cert_path) {
                    Some(c) => c,
                    None => {
                        let c = make_cert(&secret, node_id)?;
                        std::fs::create_dir_all(state)?;
                        std::fs::write(&cert_path, &c)?;
                        c
                    }
                };
                (secret, cert_der)
            }
            None => {
                let (k, c) = (read_if_exists(&key_path), read_if_exists(&cert_path));
                // Load the stored identity only when both files are present
                // and parse cleanly. A file that exists but is truncated or
                // corrupted — e.g. a hard reset interrupted the write — is
                // treated as absent and the identity is regenerated instead
                // of erroring, which would crash-loop under restart="always".
                // A regenerated identity has a fresh SPKI pin (the pin must
                // be re-established).
                let stored = match (k, c) {
                    (Some(k), Some(c)) if !c.is_empty() => {
                        std::str::from_utf8(&k)
                            .ok()
                            .and_then(|pem| pkcs8_der_from_pem(pem).ok())
                            .and_then(|der| scalar_from_pkcs8(&der).ok())
                            .map(|s| (s, c))
                    }
                    _ => None,
                };
                let (secret, cert_der) = match stored {
                    Some((s, c)) => (s, c),
                    None => {
                        let mut b = [0u8; 48];
                        rand::RngCore::fill_bytes(&mut rand::rng(), &mut b);
                        let sk = p384::SecretKey::from_slice(&b)
                            .map_err(|e| anyhow::anyhow!("generated scalar rejected: {e}"))?;
                        let secret = sk.to_bytes().to_vec().try_into().unwrap();
                        let cert_der = make_cert(&secret, node_id)?;
                        std::fs::create_dir_all(state)?;
                        std::fs::write(&key_path, pkcs8_pem(&secret)?)?;
                        std::fs::write(&cert_path, &cert_der)?;
                        (secret, cert_der)
                    }
                };
                (secret, cert_der)
            }
        };

        Ok(Self {
            pin: pin_of_cert(&cert_der).map_err(|e| anyhow::anyhow!("spki pin: {e}"))?,
            secret,
            cert_der,
        })
    }

    pub fn tls_config(&self) -> rustls::ServerConfig {
        let cert = rustls::pki_types::CertificateDer::from(self.cert_der.clone());
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_from_scalar(&self.secret));
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .expect("tls config")
    }

    /// The SPKI pin (hex).
    pub fn pin(&self) -> String {
        self.pin.clone()
    }
}

fn read_if_exists(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}

fn pkcs8_der_from_pem(pem: &str) -> anyhow::Result<Vec<u8>> {
    let der = rustls_pemfile::pkcs8_private_keys(&mut pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 key in PEM"))??;
    Ok(der.secret_pkcs8_der().to_vec())
}

fn load_pkcs8_pem(p: &Path) -> anyhow::Result<Vec<u8>> {
    let pem = std::fs::read_to_string(p)?;
    pkcs8_der_from_pem(&pem).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}

/// Extract the 48-byte P-384 scalar from a PKCS8 v1 document.
fn scalar_from_pkcs8(der: &[u8]) -> anyhow::Result<[u8; 48]> {
    use p384::pkcs8::DecodePrivateKey;
    let sk = p384::SecretKey::from_pkcs8_der(der)
        .map_err(|e| anyhow::anyhow!("pkcs8 decode: {e}"))?;
    let b = sk.to_bytes();
    if b.as_slice().len() != 48 {
        anyhow::bail!("P-384 scalar is {} bytes, expected 48", b.as_slice().len());
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(b.as_slice());
    Ok(out)
}

fn pkcs8_from_scalar(scalar: &[u8; 48]) -> Vec<u8> {
    use p384::pkcs8::EncodePrivateKey;
    let sk = p384::SecretKey::from_slice(scalar).expect("scalar is valid");
    sk.to_pkcs8_der().expect("pkcs8 encode").as_bytes().to_vec()
}

fn pkcs8_pem(scalar: &[u8; 48]) -> anyhow::Result<Vec<u8>> {
    use base64::Engine as _;
    let der = pkcs8_from_scalar(scalar);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    Ok(out.into_bytes())
}

/// Make a self-signed cert for the P-384 identity (CN = node id).
fn make_cert(secret: &[u8; 48], node_id: &str) -> anyhow::Result<Vec<u8>> {
    use rcgen::{DnType, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384};

    let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_from_scalar(secret));
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ECDSA_P384_SHA384)
        .map_err(|e| anyhow::anyhow!("keypair: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![node_id.to_string()])
        .map_err(|e| anyhow::anyhow!("cert params: {e}"))?;
    params.distinguished_name.push(DnType::CommonName, node_id.to_string());
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
    let cert = params.self_signed(&kp).map_err(|e| anyhow::anyhow!("cert sign: {e}"))?;
    Ok(cert.der().to_vec())
}

/// Detect the platform: "aws" if IMDS answers, else "baremetal".
fn detect_platform() -> String {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let ok = match TcpStream::connect_timeout(
        &"169.254.169.254:80".parse().expect("literal addr"),
        std::time::Duration::from_millis(300),
    ) {
        Ok(mut s) => {
            let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(300)));
            let wrote = s
                .write_all(b"GET /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\n\r\n")
                .is_ok();
            wrote
                && {
                    let mut buf = [0u8; 256];
                    s.read(&mut buf).is_ok()
                }
        }
        Err(_) => false,
    };
    if ok {
        "aws".into()
    } else {
        "baremetal".into()
    }
}

/// App state shared by the routes.
struct App {
    identity: Arc<Identity>,
    node_id: String,
    platform: String,
    channels: Arc<Vec<Box<dyn Channel + Send + Sync>>>,
    metadata: Option<serde_json::Value>,
}

async fn health() -> &'static str {
    "ok"
}

async fn info(State(app): State<Arc<App>>) -> Json<Info> {
    // Report the channels this node actually serves: a channel that is
    // registered but whose hardware is absent (e.g. snp on a non-SNP host)
    // is filtered out so the advertised set matches the Bundle.
    let channels: Vec<String> = app
        .channels
        .iter()
        .filter(|c| c.detect())
        .map(|c| c.name().to_string())
        .collect();
    Json(Info {
        node_id: app.node_id.clone(),
        platform: app.platform.clone(),
        channels,
        daemon_pubkey: app.identity.pin(),
        metadata: app.metadata.clone(),
    })
}

#[derive(serde::Deserialize)]
struct AttestationRequest {
    /// Client-chosen nonce (b64, 32 bytes). If absent, the server generates
    /// one and echoes it in the Bundle.
    nonce: Option<B64>,
}

async fn attestation(
    State(app): State<Arc<App>>,
    Json(req): Json<AttestationRequest>,
) -> Result<Json<Bundle>, (StatusCode, String)> {
    let nonce: [u8; 32] = match req.nonce {
        Some(n) => {
            let v: Vec<u8> = n.0;
            if v.len() != 32 {
                return Err((StatusCode::BAD_REQUEST, "nonce must be 32 bytes".into()));
            }
            let mut n = [0u8; 32];
            n.copy_from_slice(&v);
            n
        }
        None => {
            let mut n = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut n);
            n
        }
    };

    // Collect the non-tpm2 channels first, then the tpm2 channel last so it
    // can fold the other docs into the slot link before quoting. Non-tpm2
    // channels are best-effort: a channel whose hardware is absent (or whose
    // firmware request fails) is skipped with a warning so the Bundle degrades
    // to the channels actually present (tpm2-only on a non-SNP host) instead
    // of failing the request. The tpm2 channel is the mandatory core.
    let channels = app.channels.clone();
    let collected: Vec<Collected> = tokio::task::spawn_blocking(move || -> Result<Vec<Collected>, String> {
        let mut docs: Vec<Vec<u8>> = Vec::new();
        let mut out: Vec<Collected> = Vec::new();
        for c in channels.iter() {
            if c.name() == "tpm2" {
                continue;
            }
            if !c.detect() {
                info!(channel = c.name(), "channel inactive (hardware absent); degrading");
                continue;
            }
            match c.collect(&nonce, &docs) {
                Ok(col) => {
                    docs.push(col.evidence.doc.0.clone());
                    out.push(col);
                }
                Err(e) => {
                    warn!(channel = c.name(), %e, "channel collect failed; degrading");
                }
            }
        }
        for c in channels.iter() {
            if c.name() != "tpm2" {
                continue;
            }
            let col = c.collect(&nonce, &docs)?;
            out.push(col);
        }
        Ok(out)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let mut evidence = Vec::new();
    let mut keys = None;
    for col in collected {
        keys = keys.or(col.keys);
        evidence.push(col.evidence);
    }

    let bundle = Bundle {
        v: BUNDLE_V,
        nonce: B64::new(nonce.to_vec()),
        node: crate::wire::Node {
            id: app.node_id.clone(),
            platform: app.platform.clone(),
        },
        evidence,
        keys,
        metadata: app.metadata.clone(),
    };
    Ok(Json(bundle))
}

fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE])
}

/// Run the attest server.
pub async fn run(opts: Opts) -> anyhow::Result<()> {
    let node_id = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "node".into());

    let platform = detect_platform();
    info!(%node_id, %platform, "attest: identity + platform");

    let identity = Arc::new(Identity::load_or_generate(
        &opts.state,
        &node_id,
        opts.key.as_deref(),
    )?);

    let metadata = match &opts.metadata {
        Some(p) => {
            let s = std::fs::read_to_string(p)?;
            Some(serde_json::from_str(&s)?)
        }
        None => None,
    };

    let mut channels: Vec<Box<dyn Channel + Send + Sync>> = Vec::new();
    match &opts.tcp {
        Some(addr) => {
            channels.push(Box::new(tpm2::Tpm2::new("/dev/tpm0").with_tcp(addr.clone())));
            info!(tcp = %addr, "channel tpm2 active (swtpm over tcp)");
        }
        _ => {
            if let Some(dev) = tpm2::detect_device() {
                channels.push(Box::new(tpm2::Tpm2::new(dev)));
                info!("channel tpm2 active");
            } else {
                warn!("no TPM device found; the tpm2 channel is inactive");
            }
        }
    }
    // The snp channel is per-challenge in-process (SNP_GET_EXT_REPORT against
    // /dev/sev-guest). Register it only when the device is present; on a
    // non-SNP host the node serves tpm2-only and degrades gracefully.
    if crate::snp::device_present() {
        channels.push(Box::new(snp::Snp::new()));
        info!("channel snp active (/dev/sev-guest)");
    } else {
        info!("no /dev/sev-guest; the snp channel is inactive");
    }
    let channels = Arc::new(channels);

    let app = Arc::new(App {
        identity,
        node_id,
        platform,
        channels,
        metadata,
    });

    let router = axum::Router::new()
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/attestation", post(attestation).layer(cors()))
        .with_state(app.clone());

    let tls = app.identity.tls_config();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

    info!(listen = %opts.listen, pin = %app.identity.pin(), "attest: serving");
    let listener = tokio::net::TcpListener::bind(&opts.listen).await?;

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    debug!(?peer, %e, "tls handshake failed");
                    return;
                }
            };
            let stream = hyper_util::rt::TokioIo::new(tls);
            let hyper_service = hyper::service::service_fn(move |request| {
                let mut router = router.clone();
                async move { router.call(request).await }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::pkcs8::EncodePrivateKey;

    #[test]
    fn pkcs8_scalar_decode_matches_library_encode() {
        let mut b = [0u8; 48];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut b);
        let sk = p384::SecretKey::from_slice(&b).expect("valid scalar");
        let original = sk.to_bytes();
        let der = sk.to_pkcs8_der().expect("encode").as_bytes().to_vec();
        let recovered = scalar_from_pkcs8(&der).expect("decode");
        assert_eq!(recovered, original.as_slice());
    }

    #[test]
    fn pkcs8_pem_persistence_roundtrip() {
        let mut b = [0u8; 48];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut b);
        let pem = pkcs8_pem(&b).expect("pem");
        let der = pkcs8_der_from_pem(std::str::from_utf8(&pem).unwrap()).expect("decode pem");
        assert_eq!(der, pkcs8_from_scalar(&b));
        let scalar = scalar_from_pkcs8(&der).expect("scalar");
        assert_eq!(scalar, b);
    }
}
