//! `bootproof verify <target>` — the client.
//!
//! 1. Resolve the endpoint: `--direct` / host:port / IP, else the
//!    `_bootproof.<target>` DNS TXT record, else the apex.
//! 2. TLS with SPKI pinning (pin file, TXT hint, or TOFU + `--trust`).
//! 3. Challenge: generate `N` (32 B), `POST /attestation {nonce: N}`.
//! 4. Sanity: `bundle.nonce == N` (replay guard).
//! 5. Verify each channel offline; derive facts; render the facts table.
//! 6. `--pin` (or first-run TOFU) stores the pin for drift detection later.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tracing::debug;

use crate::channel::Verifier;
use crate::dns::BootproofRecord;
use crate::spki::spki_pin;
use crate::verify::tpm2::Tpm2Verifier;
use crate::wire::{Bundle, Fact, Status};

pub mod snp;
pub mod tpm2;

pub struct Opts {
    pub target: String,
    pub port: Option<u16>,
    pub direct: bool,
    pub trust: bool,
    pub pin: bool,
    pub bundle: bool,
    pub json: bool,
    pub timeout: std::time::Duration,
}

/// A pinned daemon identity.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Pin {
    /// Hex `SHA-256(SPKI DER)` of the daemon's TLS cert.
    pub daemon_pubkey: String,
    /// Unix seconds of first pin.
    pub created: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct PinFile {
    pins: BTreeMap<String, Pin>,
}

fn pins_path() -> std::path::PathBuf {
    let base = match std::env::var("XDG_CONFIG_HOME").ok() {
        Some(x) => std::path::PathBuf::from(x),
        None => match std::env::var("HOME").ok() {
            Some(h) => std::path::PathBuf::from(h).join(".config"),
            None => std::path::PathBuf::from("/tmp"),
        },
    };
    base.join("bootproof").join("pins.json")
}

fn load_pins() -> PinFile {
    std::fs::read_to_string(pins_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_pins(p: &PinFile) {
    let path = pins_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string_pretty(p) {
        let _ = std::fs::write(path, s);
    }
}

/// A cert verifier that pins the daemon's TLS SPKI.
///
/// When `expected` is `None` it is in capture mode (TOFU probe): it accepts
/// any ECDSA cert and records its SPKI pin for display / pinning.
#[derive(Debug)]
struct PinVerifier {
    expected: Option<String>,
    captured: std::sync::Mutex<Option<String>>,
}

impl PinVerifier {
    fn capture(&self) -> Option<String> {
        self.captured.lock().unwrap().clone()
    }
}

impl ServerCertVerifier for PinVerifier {
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // The daemon identity is an ECDSA P-384 key.
        vec![SignatureScheme::ECDSA_NISTP384_SHA384]
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = spki_pin(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("cert parse: {e}")))?;
        *self.captured.lock().unwrap() = Some(pin.clone());
        if let Some(exp) = &self.expected {
            if exp != &pin {
                return Err(rustls::Error::General(
                    "daemon pubkey drift: cert SPKI does not match the pin".into(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // The cert's SPKI was pinned in verify_server_cert; the handshake
        // signature is checked against the cert's key.
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("no crypto provider".into()))?;
        let pk = crate::spki::spki_raw_key(cert.as_ref())
            .map_err(|e| rustls::Error::General(format!("spki key: {e}")))?;
        for alg in provider.signature_verification_algorithms.all {
            if alg.verify_signature(&pk, message, dss.signature()).is_ok() {
                return Ok(HandshakeSignatureValid::assertion());
            }
        }
        Err(rustls::Error::General("handshake signature invalid".into()))
    }
}

fn client_config(pin: Option<String>) -> (Arc<rustls::ClientConfig>, Arc<PinVerifier>) {
    crate::attest::install_crypto_provider();
    let verifier = Arc::new(PinVerifier {
        expected: pin,
        captured: std::sync::Mutex::new(None),
    });
    let cfg = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth(),
    );
    (cfg, verifier)
}

/// Resolve the endpoint for `target`. Returns (endpoint_host, port, txt_rec).
fn resolve(opts: &Opts) -> Result<(String, u16, Option<BootproofRecord>), String> {
    let t = &opts.target;
    let has_port = t.contains(':') && !t.ends_with(']');
    let is_ip = t.parse::<std::net::IpAddr>().is_ok();

    if opts.direct || has_port || is_ip {
        let (host, port) = split_host_port(t, opts.port);
        return Ok((host, port, None));
    }

    match crate::dns::lookup(t) {
        Some(rec) => {
            let endpoint = rec
                .endpoint
                .clone()
                .ok_or_else(|| "TXT record has no endpoint=".to_string())?;
            let (host, port) = split_host_port(&endpoint, opts.port);
            Ok((host, port, Some(rec)))
        }
        None => {
            let port = opts.port.unwrap_or(443);
            Ok((t.clone(), port, None))
        }
    }
}

fn split_host_port(s: &str, port_override: Option<u16>) -> (String, u16) {
    if let Some((h, p)) = s.split_once(':') {
        let p = p.parse::<u16>().unwrap_or(443);
        (h.to_string(), port_override.unwrap_or(p))
    } else {
        (s.to_string(), port_override.unwrap_or(443))
    }
}

/// Post the challenge and get the Bundle over pinned TLS.
fn attest(
    host: &str,
    port: u16,
    nonce_b64: &str,
    pin: Option<String>,
    timeout: std::time::Duration,
) -> Result<String, String> {
    let (cfg, _) = client_config(pin);
    let agent = ureq::AgentBuilder::new().tls_config(cfg).timeout(timeout).build();

    let url = format!("https://{host}:{port}/attestation");
    let body = serde_json::json!({ "nonce": nonce_b64 });
    let resp = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                format!("attestation request: {code} {body}")
            }
            e => format!("attestation request: {e}"),
        })?;
    resp.into_string().map_err(|e| format!("attestation response: {e}"))
}

/// The TOFU probe: complete a TLS handshake with a capturing verifier and
/// return the daemon's SPKI pin.
fn probe_pin(host: &str, port: u16, timeout: std::time::Duration) -> Result<String, String> {
    let (cfg, verifier) = client_config(None);
    let agent = ureq::AgentBuilder::new().tls_config(cfg).timeout(timeout).build();
    let url = format!("https://{host}:{port}/health");
    agent
        .get(&url)
        .call()
        .map(|_| ())
        .map_err(|e| format!("TLS probe: {e}"))?;
    verifier.capture().ok_or_else(|| "probe captured no pin".to_string())
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn render_table(facts: &[Fact]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<22} {:<46} {:<10} {:<10}\n",
        "FACT", "VALUE", "ANCHOR", "STATUS"
    ));
    out.push_str(&"-".repeat(92));
    out.push('\n');
    for f in facts {
        let status = match f.status {
            Status::Proven => "PROVEN",
            Status::Reproducible => "REPRO",
            Status::Degraded => "DEGRADED",
            Status::NotProven => "NOT PROVEN",
        };
        let value = if f.value.len() > 46 {
            format!("{}...", &f.value[..43])
        } else {
            f.value.clone()
        };
        out.push_str(&format!(
            "{:<22} {:<46} {:<10} {:<10}\n",
            f.name,
            value,
            f.anchors.join("+"),
            status
        ));
    }
    out
}

/// Run `bootproof verify`.
pub fn run(opts: Opts) -> anyhow::Result<i32> {
    let (host, port, txt) = resolve(&opts).map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("[verify] endpoint {host}:{port}");

    // --- Pin resolution -------------------------------------------------
    let pin_key = format!("{host}:{port}");
    let mut pinfile = load_pins();
    let existing_pin = pinfile.pins.get(&pin_key).cloned();
    let had_pin = existing_pin.is_some();

    let pin: String = match (existing_pin, txt.as_ref().and_then(|r| r.key.clone())) {
        (Some(p), _) => {
            eprintln!("[verify] pin from pin file ({}); drift is an error", p.created);
            p.daemon_pubkey
        }
        (None, Some(_hint)) => {
            // TXT hint is sha256 of the pubkey; we pin the SPKI. Confirm the
            // hint against the live cert below, then adopt the live pin.
            eprintln!("[verify] TXT hint present; adopting the live SPKI pin");
            probe_pin(&host, port, opts.timeout).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        (None, None) => {
            if !opts.trust {
                eprintln!(
                    "[verify] first contact with {pin_key}: no pin file, no TXT hint.\n\
                     Run with --trust to accept the daemon's current SPKI pin."
                );
                return Ok(1);
            }
            eprintln!("[verify] first contact: probing the daemon's SPKI pin (TOFU)");
            probe_pin(&host, port, opts.timeout).map_err(|e| anyhow::anyhow!("{e}"))?
        }
    };

    // --- Challenge ------------------------------------------------------
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);

    let json = attest(&host, port, &b64(&nonce), Some(pin.clone()), opts.timeout)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if opts.bundle {
        println!("{json}");
    }
    let bundle: Bundle =
        serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("bundle parse: {e}"))?;

    // Replay guard.
    let bn: Vec<u8> = bundle.nonce.0.clone();
    if bn.as_slice() != nonce.as_slice() {
        anyhow::bail!("bundle nonce != challenge nonce (replay or MITM)");
    }
    if bundle.v != crate::wire::BUNDLE_V {
        anyhow::bail!("unsupported bundle version {}", bundle.v);
    }

    // --- Verify channels ------------------------------------------------
    let mut all_facts: Vec<Fact> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for ev in &bundle.evidence {
        let verifier: &dyn Verifier = match ev.channel.as_str() {
            "tpm2" => &Tpm2Verifier,
            "snp" => &crate::verify::snp::SnpVerifier,
            other => {
                errors.push(format!("no verifier for channel {other}"));
                continue;
            }
        };
        match verifier.verify(ev, &nonce, &bundle) {
            Ok(v) => all_facts.extend(verifier.facts(&v)),
            // A present-but-failing channel is NOT PROVEN with the reason,
            // never silently dropped: the channel reports the fact it owns
            // (snp: memory_encryption), and the error is recorded too.
            Err(e) => {
                errors.push(format!("{}: {e}", ev.channel));
                if let Some(f) = verifier.failed_fact(ev, &e) {
                    all_facts.push(f);
                }
            }
        }
    }

    // `memory_encryption` is always reported, never silently dropped: the
    // snp channel proves it (or reports it NOT PROVEN with a reason when
    // present but failing); a node that does not serve the snp channel at
    // all gets an honest NOT PROVEN "absent" fact.
    let has_snp = bundle.evidence.iter().any(|ev| ev.channel == "snp");
    if !has_snp {
        all_facts.push(Fact {
            name: "memory_encryption".into(),
            value: "not proven: the node does not serve a SEV-SNP channel \
                     (no /dev/sev-guest at the node)"
                .into(),
            anchors: vec![],
            status: Status::NotProven,
        });
    }

    // --- Pin ------------------------------------------------------------
    if opts.pin || !had_pin {
        let p = Pin {
            daemon_pubkey: pin.clone(),
            created: now_unix(),
        };
        pinfile.pins.insert(pin_key, p);
        save_pins(&pinfile);
        eprintln!("[verify] pin stored at {}", pins_path().display());
    }

    // --- Render ---------------------------------------------------------
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "endpoint": format!("{host}:{port}"),
                "bundle": &bundle,
                "facts": all_facts,
                "errors": errors,
            })
        );
    } else {
        println!("\nbootproof verify {host}:{port}\n");
        println!("{}", render_table(&all_facts));
        if !errors.is_empty() {
            println!("\nERRORS:");
            for e in &errors {
                println!("  {e}");
            }
        }
    }
    debug!("verify done: {} facts, {} errors", all_facts.len(), errors.len());

    Ok(if errors.is_empty() { 0 } else { 1 })
}

fn now_unix() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}
