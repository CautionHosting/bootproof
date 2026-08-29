//! `bootproof verify-nitro` — client-side verification of a NitroTPM
//! attestation against the AWS Nitro roots of trust.
//!
//! Verifies the COSE_Sign1 signature (ES384 over the `"Signature1"`
//! Sig_structure), the certificate chain to the pinned AWS Nitro Enclaves
//! root, and the nonce echo. If an expected-PCR policy is supplied, each
//! pinned PCR must match the document's `nitrotpm_pcrs`/`pcrs` map. The
//! known-good reference values are the `--pcrs` policy (establish them with
//! `--emit-pcrs` from a verified document).

use std::collections::HashMap;
use std::path::Path;

use base64::Engine as _;
use bootproof_sdk::format::nitro::{Nitro, NitroPcrs};
use bootproof_sdk::format::VerifiableSignedAttestationFormat;

/// Options for `verify-nitro`.
pub struct Opts {
    /// Path to the attestation: a `serve` JSON response, or a raw base64
    /// COSE_Sign1 document.
    pub doc: std::path::PathBuf,
    /// Expected nonce (hex or base64). If absent, a serve JSON doc's nonce is
    /// used.
    pub nonce: Option<String>,
    /// Optional JSON file of expected PCRs `{"0": "hex", ...}`. If absent,
    /// verifies signature + chain + nonce without a PCR policy.
    pub pcrs: Option<std::path::PathBuf>,
    /// Verify at this Unix time (seconds) instead of the current wall clock
    /// (for attesting a captured document whose leaf cert has since expired).
    pub time: Option<u64>,
    /// After a successful verify, write the document's PCRs to this JSON file
    /// as a known-good reference for future verifications.
    pub emit_pcrs: Option<std::path::PathBuf>,
    /// Emit JSON instead of a human-readable table.
    pub json: bool,
}

/// Verify and print. Returns a process exit code (0 = verified, 1 = failed).
pub fn run(opts: Opts) -> anyhow::Result<i32> {
    let raw = std::fs::read(&opts.doc).map_err(|e| anyhow::anyhow!("read doc: {e}"))?;
    let (data, doc_nonce) = load_doc(&raw)?;

    let nonce_bytes = match opts.nonce.as_deref() {
        Some(s) => decode_hex_or_b64(s).map_err(|e| anyhow::anyhow!("nonce: {e}"))?,
        None => doc_nonce
            .ok_or_else(|| anyhow::anyhow!("no nonce: pass --nonce, or use a serve JSON doc"))?,
    };

    let policy: NitroPcrs = match &opts.pcrs {
        Some(p) => load_pcr_policy(p)?,
        None => HashMap::new(),
    };
    let policy_len = policy.len();

    let time = match opts.time {
        Some(t) => std::time::Duration::from_secs(t),
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default(),
    };

    // Parse the doc's PCRs up front (only written if --emit-pcrs is set and
    // verification succeeds). Done before `data` moves into Nitro.
    let emit_pcrs: Option<std::collections::BTreeMap<u32, Vec<u8>>> = opts
        .emit_pcrs
        .as_ref()
        .map(|_| bootproof_tpm::attest::parse_attestation_document(&data).map(|f| f.pcrs))
        .transpose()?;

    let nitro = Nitro::with_pcr_policy(data, policy);
    match nitro.verify(time, &nonce_bytes) {
        Ok(_payload) => {
            if let (Some(out), Some(pcrs)) = (&opts.emit_pcrs, &emit_pcrs) {
                let m: serde_json::Map<String, serde_json::Value> = pcrs
                    .iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::String(hex(v))))
                    .collect();
                std::fs::write(out, serde_json::to_string_pretty(&m)?)?;
            }
            if opts.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "verified": true,
                        "signature": "valid",
                        "chain": "aws-nitro-enclaves-root",
                        "nonce": hex(&nonce_bytes),
                        "pcr_policy": policy_len,
                    })
                );
            } else {
                println!("NITRO ATTESTATION: VERIFIED");
                println!("  signature:  valid (ES384, \"Signature1\" context)");
                println!("  chain:      leaf -> ... -> AWS Nitro Enclaves root");
                println!("  nonce:      echo OK ({})", hex(&nonce_bytes));
                println!("  pcr policy: {policy_len} pinned value(s)");
            }
            Ok(0)
        }
        Err(e) => {
            if opts.json {
                println!("{}", serde_json::json!({ "verified": false, "error": e.to_string() }));
            } else {
                println!("NITRO ATTESTATION: FAILED");
                println!("  error: {e}");
            }
            Ok(1)
        }
    }
}

/// Decode the attestation from either a `serve` JSON response (with
/// `document` + `nonce`) or a raw base64 COSE_Sign1 document. Returns the raw
/// COSE bytes and, if present, the doc-carried nonce.
fn load_doc(raw: &[u8]) -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) {
        if let (Some(doc_b64), Some(nonce_hex)) = (
            v.get("document").and_then(|d| d.as_str()),
            v.get("nonce").and_then(|n| n.as_str()),
        ) {
            let data = base64_decode(doc_b64)?;
            let nonce = decode_hex_or_b64(nonce_hex)?;
            return Ok((data, Some(nonce)));
        }
    }
    let data = base64_decode(&String::from_utf8_lossy(raw))?;
    Ok((data, None))
}

/// Decode an expected-PCR policy JSON file (`{"0": "hex", ...}`).
fn load_pcr_policy(path: &Path) -> anyhow::Result<NitroPcrs> {
    let raw = std::fs::read(path).map_err(|e| anyhow::anyhow!("read pcrs: {e}"))?;
    let map: HashMap<String, String> =
        serde_json::from_slice(&raw).map_err(|e| anyhow::anyhow!("pcrs json: {e}"))?;
    let mut policy = HashMap::new();
    for (k, v) in map {
        let idx: u8 = k
            .parse()
            .map_err(|_| anyhow::anyhow!("bad pcr index {k:?}"))?;
        policy.insert(idx, decode_hex_or_b64(&v)?);
    }
    Ok(policy)
}

fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow::anyhow!("base64: {e}"))
}

fn decode_hex_or_b64(s: &str) -> anyhow::Result<Vec<u8>> {
    let t = s.trim();
    if !t.is_empty() && t.len() % 2 == 0 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return (0..t.len() / 2)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("hex: {e}"));
    }
    base64_decode(t)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
