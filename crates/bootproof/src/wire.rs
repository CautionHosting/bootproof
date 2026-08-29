//! The MVP wire types: what the node publishes and what the verifier renders.
//!
//! The whole system is "challenge -> signed evidence -> offline verify ->
//! facts". These types are the contract between `attest` (node) and `verify`
//! (client). Everything a channel produces rides in `Evidence.doc` (opaque
//! channel-specific bytes) plus `Evidence.anchors` (bundled certs/keys the
//! verifier needs to check it, e.g. the EK certificate).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use crate::b64::B64;

/// Bundle schema version. Bump when the wire shape changes.
pub const BUNDLE_V: u8 = 1;

/// How confident the verifier is in a fact. Honest degradation is the point:
/// a fact a channel cannot produce is `NotProven`, never silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Cryptographically proven from signed evidence, fully checked.
    Proven,
    /// The value is published (e.g. an image source URL) and can be
    /// independently reproduced, but reproduction was not attempted.
    Reproducible,
    /// Partially checked (e.g. an EK cert is present but its chain was not
    /// verified against roots in this build).
    Degraded,
    /// The channel is absent or the fact cannot be produced here.
    NotProven,
}

/// One derived fact about the node, with the channel(s) that anchor it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub name: String,
    pub value: String,
    /// Channel names that anchor this fact (e.g. `["tpm2"]` or
    /// `["tpm2","snp"]` when two independent channels agree).
    pub anchors: Vec<String>,
    pub status: Status,
}

/// Signed evidence from one channel, for the challenge nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Channel name: "tpm2" | "snp" | "aws-cp" | ...
    pub channel: String,
    /// Channel-specific signed evidence (opaque to the wire layer).
    pub doc: B64,
    /// Bundled anchors needed to verify the doc (EK certs, CA chains, ...).
    pub anchors: BTreeMap<String, B64>,
}

/// A state-bound TPM key published in the Bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Raw `TPMT_PUBLIC` bytes (the key's public area, including its
    /// `authPolicy`).
    pub pub_: B64,
    /// Curve name (e.g. "P-256").
    pub curve: String,
    /// Signature or encryption scheme (e.g. "ecdsa-sha256").
    pub scheme: String,
    /// PCR indices the key's policy binds (its "attested state").
    pub pcr_policy: Vec<u8>,
    /// EK-attested certificate for this key (TPM2_Certify), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_by_ek: Option<B64>,
}

/// The node's published state-bound keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keys {
    /// ECDH key for encrypt-to-machine. Absent in builds without ECDH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<KeyInfo>,
    /// ECDSA key for PCR-gated signing.
    pub sign: Option<KeyInfo>,
}

/// Node identity block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    /// "baremetal" | "aws" | "baremetal-snp" | "aws-snp"
    pub platform: String,
}

/// The attestation bundle: the only substantive response the node returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Schema version (`BUNDLE_V`).
    pub v: u8,
    /// Echo of the challenge nonce the client sent (replay guard).
    pub nonce: B64,
    pub node: Node,
    /// One entry per active channel.
    pub evidence: Vec<Evidence>,
    /// State-bound TPM keys, if a TPM is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Keys>,
    /// Operator-supplied metadata (image name, source URL, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// `GET /info` response: what the node is and which channels it serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub node_id: String,
    pub platform: String,
    pub channels: Vec<String>,
    /// Hex `SHA-256(SPKI DER)` of the daemon's TLS cert — the pin target.
    pub daemon_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}
