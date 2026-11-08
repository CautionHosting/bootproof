//! system_health::schema: THE canonical System Health presentation contract.
//!
//! These types are the ONE shape the System Health envelope takes for every
//! consumer: the server (wardend's seald builds them), the browser (the
//! service worker in `assets/system_health/verify.js` parses them), and the
//! CLI (wardenctl renders them). Server + browser + CLI all derive from THIS
//! one type definition - that is the drift-killer anchor for the schema
//! layer, per AGENTS.md ("the System Health envelope presentation schema...
//! is bootproof's"). Any client that invents its own envelope shape is by
//! definition out of contract.
//!
//! Wire compatibility: field names and JSON shape mirror EXACTLY what
//! wardend's `src/seal/src/attest_envelope.rs` + `src/seal/src/admin.rs`
//! emit today (the `json!` object literals, key for key). Nothing here
//! renames or reinterprets a field; slots wardend does not emit YET are
//! optional (`Option<T>`, serializing as `null`), so an envelope that
//! deserializes through these types re-serializes byte-comparably (serde
//! orders struct fields in declaration order, which is the emission order
//! of wardend's `json!` literals for the objects defined here).
//!
//! The honesty rule (the same one the fact schemas follow, AGENTS.md):
//! absence is a VALUE, never a fabricated healthy state. Every source that
//! can be missing has a null/empty representation here, and every verifier
//! (browser + CLI) must render those as NOT PROVEN. A null is legal and
//! honest; a missing REQUIRED key is a contract violation, which is why the
//! structs below use plain fields (not `skip_serializing_if`) for
//! always-emitted keys, and `null` (not omission) for optional values.
//!
//! Layering: these are PRESENTATION types, platform-agnostic like the rest
//! of the core. A new platform fills the same keyed slots (`metadata`
//! carries platform-sourced values as opaque `serde_json::Value` for
//! platform files like the signed IMDS document); no wardend concept leaks
//! into the core. The platform evidence builders (wardend's `build_*`
//! functions) keep the file/device reads - they hand values to THESE types.
//!
//! Increment note (golden-fixture test, increment 3): the agreement test
//! feeds one fixture envelope through `engine::verify_bundle` (Rust) and
//! the service worker (JS) and asserts identical verdicts; the identity
//! link path pins that `identity.attest_signer_spki_sha256` present +
//! `metadata.cert_chain.leaf_pem` null renders NOT PROVEN in BOTH verifiers
//! (the dual-location rule: `leaf_pem_present` in `identity` is the
//! server-side claim, the `leaf_pem` CONTENT is what the browser actually
//! hashes; the browser consults the content, never the claim).

use serde::{Deserialize, Serialize};

use crate::wire::{Bundle, Fact};

/// The full System Health envelope: the response of the attestation faces
/// (the seald admin-frame `OP_ATTEST` reply body, the `/health/api` HTTP
/// proxy of it, and what wardenctl's `status` consumes).
///
/// The server builds this per request: the bundle signs the fresh nonce,
/// so the envelope is only fresh for that challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// The signed attestation bundle (the frozen `wire::Bundle` contract -
    /// this type adds NOTHING to the bundle's byte shape; it is a
    /// passthrough so one JSON carries both the proof and its rendering).
    pub bundle: Bundle,
    /// The server-side verdict facts (`engine::verify_bundle` output, run
    /// by the server against its own bundle). The client MUST re-verify the
    /// bundle itself; these are the server's honest self-report, rendered
    /// side-by-side with the client's own verdict so a divergence is
    /// visible, not hidden.
    pub facts: Vec<Fact>,
    /// Lowercase hex of the challenge nonce the bundle answers (the
    /// envelope-level freshness marker; the channel signatures bind the
    /// nonce inside the bundle independently).
    pub nonce: String,
    /// Who the server claims its signer key is (the browser checks this
    /// against the TLS leaf it actually sees - the identity link).
    pub identity: Identity,
    /// The platform-sourced display sections (see [`Metadata`]).
    pub metadata: Metadata,
}

/// The identity section: what the SERVER can honestly say about the key
/// that signed the bundle. It proves nothing to the browser by itself -
/// the browser verifies the link itself against the leaf PEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Lowercase hex `SHA-256(SPKI DER)` of the P-256 attestation signer
    /// key, or null when the server has no signer key to name (honest
    /// absence => the browser renders the identity link NOT PROVEN).
    pub attest_signer_spki_sha256: Option<String>,
    /// Whether the server has a TLS leaf PEM on hand to publish (the
    /// server's CLAIM of presence; the leaf's content lives in
    /// `metadata.cert_chain.leaf_pem` and the browser hashes THAT, never
    /// this boolean - this field exists so the server can say "no cert
    /// yet" without shipping an empty string the browser might confuse
    /// with a parse failure).
    ///
    /// `serde(default)`: absent means the honest false (no leaf published
    /// => the identity link renders NOT PROVEN). The typed serializer
    /// always EMITS the field (it stays a plain bool, never an Option);
    /// the default only lenient-parses bytes written before the field
    /// existed. The fixture-vs-schema agreement gate keeps every fixture
    /// an EXPLICIT instance (the key is written), so lenient parsing never
    /// hides drift in the canonical fixtures.
    #[serde(default)]
    pub leaf_pem_present: bool,
}

/// The metadata section: the keyed display slots, exactly the keys wardend
/// emits today, in wardend's emission order. Platform files (IMDS docs,
/// keepd state) stay opaque `serde_json::Value`: bootproof does not
/// interpret another platform's files, it only fixes their SLOTS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// The cloud instance id, or the literal `"not set"` (the contract's
    /// honest absence string - never an empty string, never a guess).
    pub instance_id: String,
    /// The launch user-data: UTF-8 when it decodes, else lowercase hex.
    pub user_data: String,
    /// The commit hash a `wardend-commit=<hex>` user-data line CLAIMS.
    /// Parsed claim, not a proof (user-data is launch-time influenceable);
    /// null when no such line exists. The page pairs it with the measured
    /// boot facts precisely because this alone proves nothing.
    pub stagex_commit: Option<String>,
    /// The signed IMDS instance-identity document (opaque platform bytes;
    /// the browser renders, the CLI may verify against the AWS signature),
    /// or null when absent.
    pub instance_identity: Option<serde_json::Value>,
    /// The disk-encryption state file (keepd's), or null when absent.
    pub disk_encryption: Option<serde_json::Value>,
    /// The warden's runtime unit table; `[]` when absent (the honest empty
    /// table, never a fabricated unit list).
    pub units: Vec<UnitRow>,
    /// The HSM key registry: names + gating only, material never read (a
    /// read would burn the store's once-per-boot gate; see wardend
    /// `hsm_keys`). Empty until a registry exists.
    pub hsm_keys: Vec<HsmKeyRow>,
    /// The seal-state summary, or null when the server has no seal latch
    /// (a non-wardend platform legitimately has none => NOT PROVEN).
    pub seal_state: Option<SealState>,
    /// The ACME/TLS chain section (the browser's identity-link input; see
    /// [`CertChainSection`]). Always present; empty/ null leaf when the
    /// platform has no TLS cert.
    pub cert_chain: CertChainSection,
    /// Endorsement-chain PRESENCE per vendor (never a verified chain -
    /// chain verification is the client's job; see [`Endorsement`]).
    pub endorsement: Endorsement,
    /// The supply-chain SBOM the image was built with. There is NO SPDX
    /// artifact in the current images, so this is an honest null; it stays
    /// null until one exists (never fabricate one).
    pub spdx_inventory: Option<serde_json::Value>,
    /// Legacy flat key (pre-v2 readers): the raw IMDS instance document.
    /// Optional on the type so non-wardend platforms can omit it, while
    /// wardend keeps emitting it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_doc: Option<serde_json::Value>,
    /// Legacy flat key (pre-v2 readers): the disk-encryption state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_enc: Option<serde_json::Value>,
}

/// One unit row of `metadata.units` (wardend `normalize_unit_row`). The
/// normalization wardend applies (bare strings become `{name, ..null}` rows,
/// unknown keys preserved) happens on the SERVER; by the time bytes reach
/// this type every row already has the four contract keys. `health` is the
/// unit's health state; a null field is that field's honest absence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitRow {
    pub name: Option<String>,
    pub state: Option<String>,
    pub health: Option<String>,
    /// Extra detail from the platform's units file: the normalized
    /// non-object entry value, a failure note, or null. Opaque so any
    /// platform's detail shape survives the round trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    /// Unknown keys from the platform's units.json pass through untouched
    /// (wardend preserves them; dropping them here would break byte-level
    /// compatibility with what wardend emits).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One HSM key row of `metadata.hsm_keys` (wardend `hsm_keys`): a named
/// secret with the PCR gating derived from WHICH key sealed it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeyRow {
    pub name: String,
    /// True when the secret is sealed by the PCR-gated persist key (a
    /// persist-key secret is PCR-gated by construction).
    pub pcr_gated: bool,
    /// The PCR indices gating it (empty when `pcr_gated` is false).
    pub pcrs: Vec<u32>,
    /// Whether the name resolves to a usable key at all.
    pub sealed: bool,
    /// Which store backend holds it ("persist" | "volatile" style name),
    /// or null when the name routes nowhere.
    pub key_id: Option<String>,
    /// Always null in current builds, ON PURPOSE: classifying the key
    /// type requires peeking the material, which would burn the
    /// once-per-boot read gate. The null is the documented honest value.
    pub key_type: Option<String>,
}

/// The seal-state summary (wardend `seal_state_of`): the posture the
/// `OP_STATE` face returns plus the anchoring PCR policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealState {
    /// The latch posture string ("measured" | "sealed" | "unknown" |
    /// whatever the platform's latch reports; the page renders unknown
    /// honestly).
    pub posture: String,
    /// Lowercase hex SHA-256 of the bound state.
    pub state_hash: String,
    /// Number of entries in the HSM-signed state log (the chain the CLI
    /// and the browser verify inside the wardend channel doc).
    pub state_log: u64,
    /// The PCR indices the seal is anchored to.
    pub pcrs: Vec<u32>,
}

/// The ACME/TLS chain section (wardend `cert_chain`). THE identity-link
/// input for the browser: it hashes `leaf_pem`'s SPKI and compares against
/// `identity.attest_signer_spki_sha256`.
///
/// `tls_verified` is false from the server and that is honest: the signing
/// daemon never sees a TLS session, so IT cannot assert a verified chain -
/// the BROWSER (which is on the TLS session) is the one who can.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChainSection {
    /// The server's (always-false, honest) chain-verification claim.
    pub tls_verified: bool,
    /// The fullchain PEM text (leaf first), or null when no cert exists.
    pub leaf_pem: Option<String>,
    /// The decoded leaf, or null when absent or unparseable (a parse
    /// failure keeps `leaf_pem` so the browser can still do its OWN decode
    /// - the server's decode failing does not mean the browser's must).
    pub leaf: Option<CertRow>,
    /// The decoded intermediates (leaf excluded, self-signed roots
    /// excluded), in chain order.
    pub chain: Vec<CertRow>,
    /// The baked anchors the chain hashed to (deduped, chain order) - the
    /// server's claim only; the browser re-matches against ITS baked set.
    pub spki_anchors: Vec<String>,
}

/// One decoded certificate row (wardend `cert_row`). Fail-closed on the
/// server side: a structural surprise yields `CertRow::error` (only
/// `error` + `der_len` meaningful, the rest null/default), never a
/// partially fabricated row, never a panic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRow {
    /// Set only when the server's DER walk failed: the error string.
    /// When present, the browser MUST ignore the other fields and decode
    /// the PEM itself (the server's parser failed, not the cert).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Byte length of the certificate DER (always present, even on error:
    /// it costs nothing and bounds what the browser will be asked to
    /// parse).
    pub der_len: u64,
    /// Rendered subject Name (RFC2253-ish one-liner), null on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Rendered issuer Name, null on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Serial as uppercase hex (leading zeros stripped, "0" for zero),
    /// null on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Validity start, rendered "YYYY-MM-DD HH:MM:SS UTC", null on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Validity end, same rendering, null on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Lowercase hex SHA-256 of the SPKI DER: the PIN value. null on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spki_sha256: Option<String>,
    /// Lowercase hex SHA-256 of the whole cert DER (fingerprint), null on
    /// error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// issuer == subject (the self-signed test). Absent on error rows
    /// (wardend's error literal carries only error + der_len), always
    /// present on decoded rows - hence Option, not a defaulted bool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    /// The baked anchor name this cert's SPKI pins to
    /// ("ISRG Root X1" | "ISRG Root X2" | "ARK-Milan (AMD SEV-SNP)"), or
    /// null when it pins to nothing the server knows. This is the SERVER's
    /// match against the SERVER's baked set; the browser compares
    /// `spki_sha256` against ITS OWN baked set and never trusts this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
}

/// Endorsement-chain PRESENCE per vendor: what evidence the bundle carries,
/// with the anchor names the channel bundled. NEVER a verified chain - the
/// verification is the client's job (wardenctl's `verify_bundle` + the
/// service worker); this section exists so the page can show what is
/// available to verify without claiming anything about it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endorsement {
    /// The TPM2/NitroTPM side (AWS).
    pub aws: EndorsementSide,
    /// The SEV-SNP side (AMD): the VLEK -> ASVK -> pinned ARK chain's
    /// presence.
    pub amd: EndorsementSide,
}

/// One side of the endorsement section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorsementSide {
    /// Whether the bundle carries this channel's evidence at all.
    pub present: bool,
    /// Human-readable presence detail (channel name, evidence size,
    /// bundled anchor names, and the standing note that verification is
    /// the client's).
    pub detail: String,
}

/// The server-side convenience builder: assemble a complete envelope from
/// the pieces the daemon already holds (the platform supplies them; this
/// function knows NO platform semantics, it only fixes the shape).
///
/// `nonce` is the raw 32-byte challenge; it is hex-encoded here so the
/// call sites cannot disagree on the encoding.
pub fn build_envelope(
    bundle: Bundle,
    facts: Vec<Fact>,
    nonce: &[u8],
    identity: Identity,
    metadata: Metadata,
) -> Envelope {
    Envelope { bundle, facts, nonce: hex_lower(nonce), identity, metadata }
}

/// Lowercase hex (the one encoding every System Health hex field uses).
pub fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The honest defaults for a platform that has nothing to report for a
/// section: NOT PROVEN by construction, never a fabricated healthy state.
impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            instance_id: "not set".to_string(),
            user_data: String::new(),
            stagex_commit: None,
            instance_identity: None,
            disk_encryption: None,
            units: Vec::new(),
            hsm_keys: Vec::new(),
            seal_state: None,
            cert_chain: CertChainSection::default(),
            endorsement: Endorsement::absent(),
            spdx_inventory: None,
            instance_doc: None,
            disk_enc: None,
        }
    }
}

impl Default for CertChainSection {
    fn default() -> Self {
        CertChainSection {
            tls_verified: false,
            leaf_pem: None,
            leaf: None,
            chain: Vec::new(),
            spki_anchors: Vec::new(),
        }
    }
}

impl Endorsement {
    /// The absent-endorsement shape (no bundle evidence yet).
    pub fn absent() -> Self {
        Endorsement {
            aws: EndorsementSide {
                present: false,
                detail: "no bundle evidence".to_string(),
            },
            amd: EndorsementSide {
                present: false,
                detail: "no bundle evidence".to_string(),
            },
        }
    }

    /// Read endorsement PRESENCE off a bundle's evidence rows: channel,
    /// evidence length, bundled anchor names; presence only, never
    /// verification.
    ///
    /// Deliberate parity delta vs wardend's current `endorsement()`: the
    /// length is DECODED bytes, not the base64 string length wardend
    /// measures off its serialized JSON (wardend reads its own bundle
    /// `Value`, where only the encoded form exists). The decoded byte
    /// count is the honest size of the evidence; this section is presence
    /// detail, never a verification input, and the golden-fixture test
    /// (increment 3) compares VERDICTS, not this string. wardend's
    /// re-point to these types picks the corrected measure up for free
    /// (the fixture's own endorsement strings are generated through this
    /// function, so both sides of the agreement test see one source).
    pub fn from_bundle(bundle: &Bundle) -> Self {
        let mut out = Endorsement::absent();
        out.aws.detail = "no tpm2 evidence in the bundle".to_string();
        out.amd.detail = "no snp evidence in the bundle".to_string();
        for row in &bundle.evidence {
            let anchors: Vec<&str> = row.anchors.keys().map(|k| k.as_str()).collect();
            let anchor_str =
                if anchors.is_empty() { "none".to_string() } else { anchors.join(",") };
            let len = row.doc.0.len();
            match row.channel.as_str() {
                "tpm2" | "aws-cp" => {
                    out.aws.present = len > 0;
                    out.aws.detail = format!(
                        "channel {}: {len} bytes of evidence, anchors: {}",
                        row.channel, anchor_str
                    );
                }
                "snp" => {
                    out.amd.present = len > 0;
                    out.amd.detail = format!(
                        "channel {}: {len} bytes of evidence, anchors: {} \
                         (the VLEK -> ASVK -> pinned ARK-Milan chain; \
                         verification is the client's)",
                        row.channel, anchor_str
                    );
                }
                _ => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{B64, Keys, Node, Status};

    fn bundle_fixture() -> Bundle {
        Bundle {
            v: crate::wire::BUNDLE_V,
            nonce: B64(vec![0xab; 32]),
            node: Node { id: "i-0test".to_string(), platform: "aws-snp".to_string() },
            evidence: vec![
                crate::wire::Evidence {
                    channel: "snp".to_string(),
                    doc: B64(vec![1u8; 2200]),
                    anchors: Default::default(),
                },
                crate::wire::Evidence {
                    channel: "tpm2".to_string(),
                    doc: B64(vec![2u8; 1200]),
                    anchors: Default::default(),
                },
            ],
            keys: Some(Keys { enc: None, sign: None }),
            metadata: None,
        }
    }

    fn fact_fixture() -> Fact {
        Fact {
            name: "snp.nonce_binding".to_string(),
            value: "report_data binds the challenge nonce".to_string(),
            anchors: vec!["snp".to_string()],
            status: Status::Proven,
        }
    }

    /// Round-trip through the typed envelope of an ALL-NULL metadata +
    /// identity with a real bundle: every honest-absent key must survive
    /// (the NOT PROVEN path is the most important fixture).
    #[test]
    fn envelope_round_trip_all_null_metadata() {
        let env = build_envelope(
            bundle_fixture(),
            vec![fact_fixture()],
            &[0xab; 32],
            Identity { attest_signer_spki_sha256: None, leaf_pem_present: false },
            Metadata::default(),
        );
        let json = serde_json::to_value(&env).expect("encode");
        // The contract keys exist with their honest values:
        assert_eq!(json["nonce"], "ab".repeat(32));
        assert!(json["identity"]["attest_signer_spki_sha256"].is_null());
        assert_eq!(json["identity"]["leaf_pem_present"], false);
        assert_eq!(json["metadata"]["instance_id"], "not set");
        assert!(json["metadata"]["stagex_commit"].is_null());
        assert!(json["metadata"]["instance_identity"].is_null());
        assert!(json["metadata"]["disk_encryption"].is_null());
        assert_eq!(json["metadata"]["units"], serde_json::json!([]));
        assert_eq!(json["metadata"]["hsm_keys"], serde_json::json!([]));
        assert!(json["metadata"]["seal_state"].is_null());
        assert_eq!(json["metadata"]["cert_chain"]["tls_verified"], false);
        assert!(json["metadata"]["cert_chain"]["leaf_pem"].is_null());
        assert!(json["metadata"]["cert_chain"]["leaf"].is_null());
        assert_eq!(json["metadata"]["cert_chain"]["chain"], serde_json::json!([]));
        assert_eq!(json["metadata"]["cert_chain"]["spki_anchors"], serde_json::json!([]));
        assert_eq!(json["metadata"]["endorsement"]["aws"]["present"], false);
        assert_eq!(json["metadata"]["endorsement"]["amd"]["present"], false);
        assert!(json["metadata"]["spdx_inventory"].is_null());
        // Legacy flat keys are OMITTED by a non-wardend producer (they are
        // optional at the type level, wardend fills them):
        assert!(json["metadata"].get("instance_doc").is_none());
        assert!(json["metadata"].get("disk_enc").is_none());
        // And the typed round trip is lossless:
        let back: Envelope = serde_json::from_value(json.clone()).expect("decode");
        assert_eq!(back.nonce, env.nonce);
        assert_eq!(back.bundle.nonce, env.bundle.nonce);
        let again = serde_json::to_value(&back).expect("re-encode");
        assert_eq!(json, again, "round trip is not stable");
    }

    /// A wardend-shaped fixture (the keys + order wardend's json! literals
    /// emit) deserializes into the typed envelope with ZERO loss: this is
    /// the wardend byte-compatibility gate. The fixture mirrors
    /// admin.rs's envelope assembly + attest_envelope's section builders
    /// with the ACME-not-issued nulls.
    #[test]
    fn wardend_shaped_envelope_deserializes_losslessly() {
        let fixture = serde_json::json!({
            "bundle": {
                "v": 1,
                "nonce": "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=",
                "node": {"id": "i-0test", "platform": "aws-snp"},
                "evidence": [
                    {"channel": "snp", "doc": "AQEB", "anchors": {}},
                    {"channel": "tpm2", "doc": "AgIC", "anchors": {}}
                ],
                "keys": {"sign": null}
            },
            "facts": [{
                "name": "snp.vmpl_zero",
                "value": "VMPL 0",
                "anchors": ["snp"],
                "status": "proven"
            }],
            "nonce": "abababababababababababababababababababababababababababababababab",
            "identity": {
                "attest_signer_spki_sha256": "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
                "leaf_pem_present": false
            },
            "metadata": {
                "instance_id": "i-0123456789abcdef0",
                "user_data": "#!/bin/sh\nwardend-commit=deadbeef1234567\n",
                "stagex_commit": "deadbeef1234567",
                "instance_identity": {
                    "document": {"instanceId": "i-0123456789abcdef0"},
                    "signature": "ZmFrZQ==",
                    "region": "us-east-1",
                    "availabilityZone": "us-east-1a"
                },
                "disk_encryption": {
                    "status": "unsealed",
                    "pcrs": [4, 5, 7, 9]
                },
                "units": [
                    {"name": "seald", "state": "active", "health": "healthy",
                     "detail": null, "extra_claim": "passes through"}
                ],
                "hsm_keys": [
                    {"name": "disk-key", "pcr_gated": true, "pcrs": [4, 5, 7, 9],
                     "sealed": true, "key_id": "persist", "key_type": null},
                    {"name": "acme-account", "pcr_gated": false, "pcrs": [],
                     "sealed": true, "key_id": "volatile", "key_type": null}
                ],
                "seal_state": {
                    "posture": "sealed",
                    "state_hash": "31d6cfe0d16ae3b7db07c7c98a60f5a50f7c9fb9e3e1b2a5a8c2bbdd6f7e2a11",
                    "state_log": 7,
                    "pcrs": [4, 5, 7, 9]
                },
                "cert_chain": {
                    "tls_verified": false,
                    "leaf_pem": null,
                    "leaf": null,
                    "chain": [],
                    "spki_anchors": []
                },
                "endorsement": {
                    "aws": {"present": true,
                            "detail": "channel tpm2: 1200 bytes of evidence, anchors: none"},
                    "amd": {"present": true,
                            "detail": "channel snp: 2200 bytes of evidence, anchors: none (the VLEK -> ASVK -> pinned ARK-Milan chain; verification is the client's)"}
                },
                "spdx_inventory": null,
                "instance_doc": {"instanceId": "i-0123456789abcdef0"},
                "disk_enc": {"status": "unsealed"}
            }
        });
        let env: Envelope = serde_json::from_value(fixture.clone()).expect("decode wardend shape");
        assert_eq!(env.identity.attest_signer_spki_sha256.as_deref(),
            Some("9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9"));
        assert!(!env.identity.leaf_pem_present);
        assert_eq!(env.metadata.units.len(), 1);
        // The unknown key in the unit row survived the decode:
        assert_eq!(env.metadata.units[0].extra["extra_claim"], "passes through");
        let hsm = &env.metadata.hsm_keys[0];
        assert!(hsm.pcr_gated);
        assert_eq!(hsm.pcrs, vec![4, 5, 7, 9]);
        assert!(hsm.key_type.is_none());
        let seal = env.metadata.seal_state.clone().expect("seal_state present");
        assert_eq!(seal.posture, "sealed");
        assert_eq!(seal.state_log, 7);
        // The legacy flat keys decode through the optional fields:
        assert!(env.metadata.instance_doc.is_some());
        assert!(env.metadata.disk_enc.is_some());
        // Re-encoding keeps every wardend key (byte-compat direction 2):
        let out = serde_json::to_value(&env).expect("encode back");
        for key in ["instance_id", "user_data", "stagex_commit", "instance_identity",
                    "disk_encryption", "units", "hsm_keys", "seal_state", "cert_chain",
                    "endorsement", "spdx_inventory", "instance_doc", "disk_enc"] {
            assert!(out["metadata"].get(key).is_some(), "wardend key {key} lost on re-encode");
        }
        assert_eq!(out["metadata"]["units"][0]["extra_claim"], "passes through");
        assert_eq!(out["nonce"], fixture["nonce"]);
        assert_eq!(out["identity"], fixture["identity"]);
        assert_eq!(out["metadata"]["endorsement"], fixture["metadata"]["endorsement"]);
    }

    /// cert_row's fail-closed error shape: only error + der_len carry
    /// meaning, everything else is null/default, and the row still
    /// round-trips (the browser must be able to SEE the failure).
    #[test]
    fn cert_row_error_shape_round_trips() {
        let row = serde_json::json!({"error": "not a SEQUENCE (tag 0x05)", "der_len": 7});
        let parsed: CertRow = serde_json::from_value(row.clone()).expect("error row decodes");
        assert_eq!(parsed.error.as_deref(), Some("not a SEQUENCE (tag 0x05)"));
        assert_eq!(parsed.der_len, 7);
        assert!(parsed.subject.is_none());
        assert!(parsed.spki_sha256.is_none());
        assert!(parsed.self_signed.is_none());
        assert!(parsed.anchor.is_none());
        // wardend emits ONLY the two keys on error (json! literal), and so
        // must we, by skip_serializing_if:
        let out = serde_json::to_value(&parsed).expect("encode");
        assert_eq!(out, row, "error row must serialize exactly {{error, der_len}}");
    }

    /// A fully-populated cert row (the ACME-issued leaf case) with the
    /// anchor slot set, and the identity-link fields it pairs with.
    #[test]
    fn cert_row_full_shape_round_trips() {
        let row = serde_json::json!({
            "subject": "CN=boot.example.com",
            "issuer": "C=US,O=Let's Encrypt,CN=R12",
            "serial": "04E1A7A3D5C9B0F2",
            "not_before": "2026-11-01 00:00:00 UTC",
            "not_after": "2027-01-30 00:00:00 UTC",
            "spki_sha256": "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
            "fingerprint": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "der_len": 1639,
            "self_signed": false,
            "anchor": "ARK-Milan (AMD SEV-SNP)"
        });
        let parsed: CertRow = serde_json::from_value(row.clone()).expect("full row decodes");
        assert_eq!(parsed.subject.as_deref(), Some("CN=boot.example.com"));
        assert_eq!(parsed.anchor.as_deref(), Some("ARK-Milan (AMD SEV-SNP)"));
        assert_eq!(parsed.self_signed, Some(false));
        let out = serde_json::to_value(&parsed).expect("encode");
        assert_eq!(out, row, "full row must round-trip byte-comparably");
    }

    /// A self-signed root row carries self_signed=true and no anchor.
    #[test]
    fn cert_row_self_signed_round_trips() {
        let row = serde_json::json!({
            "subject": "CN=ISRG Root X1",
            "issuer": "CN=ISRG Root X1",
            "serial": "8210CFB0D240E3594463E0BB63828B00",
            "not_before": "2015-06-04 11:04:38 UTC",
            "not_after": "2035-06-04 11:04:38 UTC",
            "spki_sha256": "0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3",
            "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "der_len": 1086,
            "self_signed": true,
            "anchor": "ISRG Root X1"
        });
        let parsed: CertRow = serde_json::from_value(row.clone()).expect("decode");
        assert_eq!(parsed.self_signed, Some(true));
        let out = serde_json::to_value(&parsed).expect("encode");
        assert_eq!(out, row);
    }

    /// The dual-location identity rule (the increment-3 fixture path):
    /// identity present + leaf null is LEGAL on the wire (the browser
    /// renders NOT PROVEN, and must not treat it as FAILED).
    #[test]
    fn identity_present_leaf_null_is_legal_and_honest() {
        let json = serde_json::json!({
            "bundle": {
                "v": 1, "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "node": {"id": "n1", "platform": "baremetal"},
                "evidence": []
            },
            "facts": [],
            "nonce": "0000000000000000000000000000000000000000000000000000000000000000",
            "identity": {
                "attest_signer_spki_sha256": "c0ffee0000000000000000000000000000000000000000000000000000000000",
                "leaf_pem_present": false
            },
            "metadata": {
                "instance_id": "not set", "user_data": "", "stagex_commit": null,
                "instance_identity": null, "disk_encryption": null, "units": [],
                "hsm_keys": [], "seal_state": null,
                "cert_chain": {"tls_verified": false, "leaf_pem": null, "leaf": null,
                               "chain": [], "spki_anchors": []},
                "endorsement": {"aws": {"present": false, "detail": "no bundle evidence"},
                                "amd": {"present": false, "detail": "no bundle evidence"}},
                "spdx_inventory": null
            }
        });
        let env: Envelope = serde_json::from_value(json.clone()).expect("dual-location case decodes");
        assert!(env.identity.attest_signer_spki_sha256.is_some());
        assert!(!env.identity.leaf_pem_present);
        assert!(env.metadata.cert_chain.leaf_pem.is_none());
        // And the endorsement section survives without a bundle:
        assert!(!env.metadata.endorsement.amd.present);
        let out = serde_json::to_value(&env).expect("encode");
        assert_eq!(out, json, "minimal envelope round-trips byte-comparably");
    }

    /// A units row emitted as wardend's normalized full four-key row
    /// round-trips with all-null fields (the string-entry normalized case
    /// after wardend's normalize_unit_row has run).
    #[test]
    fn unit_row_all_null_round_trips() {
        let row = serde_json::json!({
            "name": "warden.target", "state": null, "health": null, "detail": null
        });
        let parsed: UnitRow = serde_json::from_value(row.clone()).expect("decode");
        assert_eq!(parsed.name.as_deref(), Some("warden.target"));
        assert!(parsed.state.is_none() && parsed.health.is_none() && parsed.detail.is_none());
        let out = serde_json::to_value(&parsed).expect("encode");
        // detail is skip_serializing_if none, so the honest null-detail
        // normalizes to omission on OUR side; wardend emits the explicit
        // null. Both decode here; the flatten extra-map keeps wardend's
        // byte-exact emission available by NOT default-filling fields.
        assert_eq!(out["name"], "warden.target");
        assert_eq!(out["state"], serde_json::Value::Null);
        assert_eq!(out["health"], serde_json::Value::Null);
        assert!(out.get("detail").is_none());
    }

    /// Endorsement presence computed from bundle evidence: presence flags,
    /// anchor names, and the standing "verification is the client's" note
    /// (decoded-byte lengths: this function is THE endorsement-section
    /// source, both server and fixture use it).
    #[test]
    fn endorsement_from_bundle_reports_presence_and_anchors() {
        let b = bundle_fixture();
        let e = Endorsement::from_bundle(&b);
        assert!(e.aws.present && e.amd.present);
        assert_eq!(e.aws.detail, "channel tpm2: 1200 bytes of evidence, anchors: none");
        assert!(e.amd.detail.starts_with("channel snp: 2200 bytes of evidence, anchors: none "));
        assert!(e.amd.detail.contains("verification is the client's"));
        // A channel with no evidence bytes is honestly not present.
        let mut empty_doc = bundle_fixture();
        empty_doc.evidence[0].doc = B64(vec![]);
        let e1 = Endorsement::from_bundle(&empty_doc);
        assert!(!e1.amd.present);
        assert_eq!(e1.amd.detail, "channel snp: 0 bytes of evidence, anchors: none (the VLEK -> ASVK -> pinned ARK-Milan chain; verification is the client's)");
        // Anchor names ride through in the detail (bundled-key presence).
        let mut with_anchor = bundle_fixture();
        with_anchor.evidence[0]
            .anchors
            .insert("asvk".to_string(), B64(vec![9u8; 4]));
        let e2 = Endorsement::from_bundle(&with_anchor);
        assert!(e2.amd.detail.contains("anchors: asvk"));
        // Empty bundle: the honest absent detail strings.
        let empty = Bundle {
            v: 1,
            nonce: B64(vec![0u8; 32]),
            node: Node { id: "n".to_string(), platform: "baremetal".to_string() },
            evidence: vec![],
            keys: None,
            metadata: None,
        };
        let e3 = Endorsement::from_bundle(&empty);
        assert_eq!(e3.aws.detail, "no tpm2 evidence in the bundle");
        assert_eq!(e3.amd.detail, "no snp evidence in the bundle");
    }

    /// Hex encoding is lowercase, fixed width (the one encoding every
    /// System Health hex field uses).
    #[test]
    fn hex_lower_is_canonical() {
        assert_eq!(hex_lower(&[0x0a, 0xff, 0x00]), "0aff00");
    }
}
