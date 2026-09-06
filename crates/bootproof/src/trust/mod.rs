//! `bootproof verify` (no target) — the local trust tree.
//!
//! Renders a human-friendly trust tree of the system this process runs on.
//! Top-level facts are **vendor-agnostic** and dead simple, each carrying a
//! 4-state verdict; vendor/platform-specific detail (SEV-SNP, NitroTPM, IMDS,
//! sysfs) lives in evidence **sub-branches**.
//!
//! Branches, in order: **Cryptography, Custody, Security, Access, Hardware,
//! Software**.
//! Default output is a **succinct summary** (most important facts + the
//! vendor root(s) — AWS / AMD — whose attestation proves each); `--expert`
//! renders the full evidence tree. `--json` emits whichever view is selected
//! (summary by default, full tree with `--expert`).
//!
//! Verdict scale (honest degradation is the point):
//!   `true`    — anchored to a pinned trusted root by signature (+ freshness
//!               where applicable). Two roots are pinned in this binary:
//!               * AWS Nitro Enclaves root CA (NitroTPM attestation doc,
//!                 ES384, TPM2_GetRandom nonce echo for freshness), and
//!               * AMD KDS ARK (ARK-Milan): the platform-provisioned VLEK
//!                 certificate chains to it via ASVK (SEV-VLEK-Milan), and
//!                 the SEV-SNP report signature + TCB fields verify against
//!                 that VLEK.
//!               A malicious guest/platform cannot forge these without
//!               breaking the signatures or the pins.
//!   `likely`  — signed by a key the platform provisions but NOT verified to
//!               the vendor's root CA, or self-reported by the guest kernel
//!               (/proc, /sys). A malicious system could lie about these;
//!               they are reported as best observed.
//!   `false`   — verified absence
//!   `unknown` — undeterminable from the guest
//!
//! Attestation levels (derived from which pinned roots actually verified,
//! never from what the guest claims):
//!   `L0` — software TPM: a TPM2 interface responds, but the attestation
//!          does not verify to any pinned hardware vendor root (swtpm, or
//!          vendor hardware whose root is not pinned in this binary).
//!   `L1` — hardware TPM: the attestation chain verifies to a pinned
//!          vendor root (today AWS Nitro Enclaves; GCP/Azure roots to
//!          follow).
//!   `L2` — CVM dual attestation: L1 plus a CPU-attested report (SEV-SNP
//!          or TDX) verified to its own pinned root, cross-bound to the
//!          TPM document by a fresh shared nonce.
//!   `L3` — ring isolation: L2 plus an SVSM attested from a ring the
//!          hypervisor cannot reach (SVSM + coconut-svsm). Reserved.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use bootproof_sdk::format::nitro::Nitro;

// AMD KDS chain for Milan VLEK, pinned at build time (fetched from
// https://kdsintf.amd.com/vlek/v1/Milan/cert_chain on 2026-08-26; see
// data/README.md for provenance + fingerprints).
const AMD_ASVK_MILAN_PEM: &[u8] = include_bytes!("data/asvk-sev-vlek-milan.pem");
const AMD_ARK_MILAN_PEM: &[u8] = include_bytes!("data/ark-milan.pem");

// AWS instance-identity-document DSA signing certificates, one per region,
// pinned at build time. AWS publishes these per region at
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html
// (fetched 2026-08-27; provenance in data/iidd/README.md). The IIDD's
// PKCS#7 (DSA/SHA-1) signature verifies against exactly one of them.
const IIDD_DSA_CERTS: &[(&str, &str)] = &[
    ("af-south-1", include_str!("data/iidd/af-south-1.pem")),
    ("ap-east-1", include_str!("data/iidd/ap-east-1.pem")),
    ("ap-east-2", include_str!("data/iidd/ap-east-2.pem")),
    ("ap-northeast-1", include_str!("data/iidd/ap-northeast-1.pem")),
    ("ap-northeast-2", include_str!("data/iidd/ap-northeast-2.pem")),
    ("ap-northeast-3", include_str!("data/iidd/ap-northeast-3.pem")),
    ("ap-south-1", include_str!("data/iidd/ap-south-1.pem")),
    ("ap-south-2", include_str!("data/iidd/ap-south-2.pem")),
    ("ap-southeast-1", include_str!("data/iidd/ap-southeast-1.pem")),
    ("ap-southeast-2", include_str!("data/iidd/ap-southeast-2.pem")),
    ("ap-southeast-3", include_str!("data/iidd/ap-southeast-3.pem")),
    ("ap-southeast-4", include_str!("data/iidd/ap-southeast-4.pem")),
    ("ap-southeast-5", include_str!("data/iidd/ap-southeast-5.pem")),
    ("ap-southeast-6", include_str!("data/iidd/ap-southeast-6.pem")),
    ("ap-southeast-7", include_str!("data/iidd/ap-southeast-7.pem")),
    ("ca-central-1", include_str!("data/iidd/ca-central-1.pem")),
    ("ca-west-1", include_str!("data/iidd/ca-west-1.pem")),
    ("cn-north-1", include_str!("data/iidd/cn-north-1.pem")),
    ("cn-northwest-1", include_str!("data/iidd/cn-northwest-1.pem")),
    ("eu-central-1", include_str!("data/iidd/eu-central-1.pem")),
    ("eu-central-2", include_str!("data/iidd/eu-central-2.pem")),
    ("eu-north-1", include_str!("data/iidd/eu-north-1.pem")),
    ("eu-south-1", include_str!("data/iidd/eu-south-1.pem")),
    ("eu-south-2", include_str!("data/iidd/eu-south-2.pem")),
    ("eu-west-1", include_str!("data/iidd/eu-west-1.pem")),
    ("eu-west-2", include_str!("data/iidd/eu-west-2.pem")),
    ("eu-west-3", include_str!("data/iidd/eu-west-3.pem")),
    ("eusc-de-east-1", include_str!("data/iidd/eusc-de-east-1.pem")),
    ("il-central-1", include_str!("data/iidd/il-central-1.pem")),
    ("me-central-1", include_str!("data/iidd/me-central-1.pem")),
    ("me-south-1", include_str!("data/iidd/me-south-1.pem")),
    ("mx-central-1", include_str!("data/iidd/mx-central-1.pem")),
    ("sa-east-1", include_str!("data/iidd/sa-east-1.pem")),
    ("us-east-1", include_str!("data/iidd/us-east-1.pem")),
    ("us-east-2", include_str!("data/iidd/us-east-2.pem")),
    ("us-gov-east-1", include_str!("data/iidd/us-gov-east-1.pem")),
    ("us-gov-west-1", include_str!("data/iidd/us-gov-west-1.pem")),
    ("us-west-1", include_str!("data/iidd/us-west-1.pem")),
    ("us-west-2", include_str!("data/iidd/us-west-2.pem")),];
use bootproof_sdk::format::VerifiableSignedAttestationFormat;
use num_bigint::BigUint;
use num_traits::Zero as _;
use sha2::Digest as _;
use x509_parser::prelude::FromDer;

// ── data model ────────────────────────────────────────────────────────────────

/// How confident we are in a fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Cryptographically proven from signed evidence, fully checked.
    True,
    /// Strong inference / cross-anchored declared, not independently proven.
    Likely,
    /// Verified absence.
    False,
    /// Undeterminable from the guest.
    Unknown,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Verdict::True => "true",
            Verdict::Likely => "likely",
            Verdict::False => "false",
            Verdict::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Attestation strength, derived from which pinned roots actually verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// No TPM2 interface at all.
    None,
    /// Software/unproven TPM2: the device responds but no pinned vendor
    /// root verified (swtpm, or vendor hardware without a pinned root).
    L0,
    /// Hardware TPM: attestation chain verified to a pinned vendor root.
    L1,
    /// CVM dual attestation: L1 plus a CPU-attested report (SEV-SNP/TDX)
    /// verified to its own pinned root, cross-bound by a fresh nonce.
    L2,
    /// Ring isolation: L2 plus an SVSM attested from a ring the hypervisor
    /// cannot reach (SVSM + coconut-svsm). Reserved; not yet reachable.
    L3,
}

impl TrustLevel {
    /// Derive the level from the anchors. A CVM report alone is NOT L2:
    /// the model requires the TPM side of the dual attestation too.
    fn derive(nitro: &NitroFacts, snp: &SnpFacts, tpm_present: bool) -> TrustLevel {
        if nitro.ok && snp.amd_anchored() && snp.report_data.is_some() {
            return TrustLevel::L2;
        }
        if nitro.ok {
            return TrustLevel::L1;
        }
        if tpm_present {
            return TrustLevel::L0;
        }
        TrustLevel::None
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => TrustLevel::L0,
            1 => TrustLevel::L1,
            2 => TrustLevel::L2,
            3 => TrustLevel::L3,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            TrustLevel::None => "none",
            TrustLevel::L0 => "L0",
            TrustLevel::L1 => "L1",
            TrustLevel::L2 => "L2",
            TrustLevel::L3 => "L3",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            TrustLevel::None => "no TPM2 interface",
            TrustLevel::L0 => "software/unproven TPM2 (no pinned vendor root)",
            TrustLevel::L1 => "hardware TPM verified to a pinned vendor root",
            TrustLevel::L2 => "CVM dual attestation (hardware TPM + CPU-attested report, cross-bound)",
            TrustLevel::L3 => "ring isolation (SVSM)",
        }
    }
}

/// One piece of vendor-specific evidence supporting a fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence source/channel (e.g. "sev-snp", "nitro-tpm", "imds", "sysfs").
    pub source: String,
    /// Human-readable detail of what was observed.
    pub detail: String,
    /// The strength of this particular piece of evidence.
    pub proof: Verdict,
}

/// One top-level, vendor-agnostic fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    /// Fact name (e.g. "Memory Encryption").
    pub name: String,
    /// Short value (e.g. "SEV-SNP per-VM key + TSME", or "N/A").
    pub value: String,
    /// The fact's verdict.
    pub verdict: Verdict,
    /// Vendor-specific evidence sub-branches.
    pub evidence: Vec<Evidence>,
}

/// A top-level branch (Cryptography, Security, Hardware, Software).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub name: String,
    pub facts: Vec<Fact>,
}

/// The whole trust tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustTree {
    /// Branches in display order: Cryptography, Security, Hardware, Software.
    pub branches: Vec<Branch>,
}

// ── gatherer results ──────────────────────────────────────────────────────────

/// NitroTPM attestation evidence (best-effort; `ok` false on any failure).
#[derive(Debug, Clone, Default)]
struct NitroFacts {
    /// Whether the attestation fetched AND verified to the AWS Nitro root.
    ok: bool,
    /// Whether a TPM2 interface opened and responded at all (device present,
    /// whether or not its attestation verified to a pinned root).
    device: bool,
    /// Whether the signature + chain + nonce verified (== ok on success).
    chain: bool,
    /// Module identity (e.g. `i-02a44cb68978c43af-tpm...`).
    module_id: Option<String>,
    /// Region extracted from the certificate chain CNs (proven).
    region: Option<String>,
    /// Number of PCR values in the signed document.
    pcr_count: usize,
    /// Certificate chain CNs, leaf first (attestation cert + CA bundle).
    chain_cns: Vec<String>,
    /// SHA-256 fingerprint of the pinned (embedded) AWS root CA.
    root_fp: Option<String>,
    /// CN of the pinned (embedded) AWS root CA.
    root_cn: Option<String>,
    /// A short human-readable failure reason (when not ok).
    error: Option<String>,
    /// Number of PINNED expected-PCR values that the attested doc was
    /// verified against (0 = no policy: drift between boots is not detected).
    policy_len: usize,
    /// Declared provenance of the expected values (e.g. the hash-locked
    /// source the verifier rebuilt locally to derive them).
    policy_source: Option<String>,
    /// Caller metadata placed in the NSM request; the signer echoes it
    /// into the attestation document, so it sits inside the ES384
    /// signature that chains to the pinned AWS Nitro root, in the same
    /// signed blob as the PCRs, nonce, and module id.
    user_data: Option<Vec<u8>>,
}

/// SEV-SNP attestation-report evidence (from `snpguest display report`).
#[derive(Debug, Clone, Default)]
struct SnpFacts {
    /// Whether `/dev/sev-guest` is present.
    present: bool,
    /// Whether a report was fetched and displayed.
    report: bool,
    /// CPUID family id (from the report).
    cpuid_family: Option<String>,
    /// CPUID model id.
    cpuid_model: Option<String>,
    /// CPUID stepping.
    cpuid_stepping: Option<String>,
    /// Guest policy hex (e.g. "2030000").
    policy: Option<String>,
    /// SMT Allowed (guest policy).
    smt_allowed: Option<bool>,
    /// Debug Allowed (guest policy).
    debug_allowed: Option<bool>,
    /// Page Swap Disable (guest policy).
    page_swap_disable: Option<bool>,
    /// TSME (total memory encryption) enabled (platform info).
    tsme: Option<bool>,
    /// ECC enabled (platform info).
    ecc: Option<bool>,
    /// VMPL the guest runs at.
    vmpl: Option<String>,
    /// Signing key (e.g. "vlek").
    signing_key: Option<String>,
    /// Launch measurement hex (first 16 bytes, truncated).
    measurement: Option<String>,
    /// SNP firmware current version (e.g. "1.58.1").
    version: Option<String>,
    /// TCB microcode version.
    tcb_microcode: Option<String>,
    /// Whether `snpguest verify attestation` confirmed the report signature
    /// against the platform-provisioned VLEK (None = not attempted).
    vlek_verified: Option<bool>,
    /// Whether `snpguest verify certs` confirmed VLEK cert -> ASVK -> ARK
    /// (None = not attempted).
    amd_chain_ok: Option<bool>,
    /// CN of the platform-provisioned VLEK certificate (if it's a cert).
    vlek_cert_cn: Option<String>,
    /// VLEK cert notAfter (if parseable).
    vlek_cert_not_after: Option<String>,
    /// The report's 64-byte report_data (set at request time; covered by the
    /// report signature). Only set when a FRESH report was fetched this run.
    report_data: Option<Vec<u8>>,
}

/// Whether the SEV-SNP report is fully anchored to AMD's root of trust:
/// report signature verified against the platform VLEK AND the VLEK
/// certificate chains to the pinned ARK-Milan via ASVK (SEV-VLEK-Milan).
impl SnpFacts {
    fn amd_anchored(&self) -> bool {
        self.report
            && self.vlek_verified == Some(true)
            && self.amd_chain_ok == Some(true)
    }
}

/// AWS IMDS evidence (best-effort; empty if not on EC2).
#[derive(Debug, Clone, Default)]
struct ImdsFacts {
    region: Option<String>,
    az: Option<String>,
    instance_id: Option<String>,
    instance_type: Option<String>,
    /// IAM account id (from the instance-profile ARN).
    account: Option<String>,
    /// Instance role name.
    role: Option<String>,
}

/// Signed instance identity document evidence (best-effort; `verified` false
/// on any failure). The IIDD is a JSON document AWS signs per instance
/// launch; its PKCS#7 (DSA/SHA-1) signature verifies against the pinned
/// per-region AWS DSA certificate, making account/instance-type/region
/// provider-attested rather than guest-asserted.
#[derive(Debug, Clone, Default)]
struct IiddFacts {
    /// Whether the PKCS#7 signature verified against a pinned AWS cert.
    verified: bool,
    /// accountId from the signed document.
    account: Option<String>,
    /// instanceType from the signed document.
    instance_type: Option<String>,
    /// region from the signed document.
    region: Option<String>,
    /// instanceId from the signed document.
    instance_id: Option<String>,
    /// Which pinned certificate region verified (None if unverified).
    cert_region: Option<String>,
    /// A short human-readable failure reason (when not verified).
    error: Option<String>,
}

/// Guest-local evidence (CPU/OS/kernel/hardening/NIC/memory/LUKS/UEFI).
#[derive(Debug, Clone, Default)]
struct GuestFacts {
    os: Option<String>,
    kernel: Option<String>,
    hostname: Option<String>,
    cpu_model: Option<String>,
    mem_total_kb: Option<u64>,
    /// UEFI firmware active (`/sys/firmware/efi` present).
    uefi: bool,
    /// Secure Boot state: Some(true) active, Some(false) no UEFI, None unknown.
    secure_boot: Option<bool>,
    /// A LUKS/cryptsetup device registered in the guest.
    luks: bool,
    /// Whether dm-0's table is a `crypt` target (None if not exposed).
    dm0_crypt: Option<bool>,
    // CPU hardening flags (from /proc/cpuinfo "flags").
    smap: bool,
    smep: bool,
    ibpb: bool,
    stibp: bool,
    rdrand: bool,
    rdseed: bool,
    /// /dev/hwrng present.
    hwrng: bool,
    /// eth0 NIC driver name.
    nic_driver: Option<String>,
    /// eth0 NIC vendor id (hex string, e.g. "0x1d0f").
    nic_vendor: Option<String>,
    /// IOMMU groups exposed to the guest.
    iommu: bool,
    /// Key kernel hardening options from /proc/config.gz (name, enabled).
    kernel_hardening: Option<Vec<(String, bool)>>,
    // Administrative-access signals.
    /// Real uid of this process (0 = root).
    uid: Option<u32>,
    /// An SSH server is present/configured.
    sshd: bool,
    /// A serial console is enabled in the kernel cmdline.
    serial_console: bool,
    /// Whether the LUKS/dm-crypt device is TPM2-bound (if detectable).
    luks_tpm_bound: bool,
}

// ── gatherers ─────────────────────────────────────────────────────────────────

/// Fetch + verify a NitroTPM attestation, and pull the region from its cert chain.
/// When `binding_nonce` is Some (32 bytes), it is used as the document nonce
/// instead of a fresh TPM2_GetRandom — this binds the TPM document to the
/// SEV-SNP report's report_data (cross-attestation binding).
/// Decode a hex or base64 encoded PCR value.
fn decode_pcr_value(s: &str) -> anyhow::Result<Vec<u8>> {
    let t = s.trim();
    if !t.is_empty() && t.len() % 2 == 0 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        let b = (0..t.len() / 2)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        return Ok(b);
    }
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|e| anyhow::anyhow!("base64: {e}"))?)
}

/// A pinned expected-PCR policy, optionally with source provenance.
#[derive(Debug, Clone, Default)]
struct PcrPolicy {
    values: std::collections::HashMap<u8, Vec<u8>>,
    /// Where the expected values come from: an operator-captured baseline
    /// (no source) or a hash-locked source the verifier rebuilt locally to
    /// DERIVE the measurements (reproducible-build anchor).
    source: Option<String>,
}

/// Load a pinned expected-PCR policy.
/// v1: `{"<index>": "<hex|b64>"}` (operator-captured baseline; establish with
/// `bootproof verify-nitro --emit-pcrs`).
/// v2: `{"source": "<hash-locked source>", "pcrs": {...}}` (values derived
/// from a locally rebuilt image — the reproducible-build anchor).
fn load_pcr_policy_file(path: &PathBuf) -> anyhow::Result<PcrPolicy> {
    let raw = std::fs::read(path).map_err(|e| anyhow::anyhow!("read pcr policy: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| anyhow::anyhow!("pcr policy json: {e}"))?;
    let (source, pcrs_value) = match v.as_object().and_then(|o| o.get("pcrs")) {
        Some(p) => (
            v.as_object()
                .and_then(|o| o.get("source"))
                .and_then(|s| s.as_str())
                .map(str::to_string),
            p.clone(),
        ),
        None => (None, v),
    };
    let pcrs = pcrs_value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("pcr policy: not an object"))?;
    let mut values = std::collections::HashMap::new();
    for (k, val) in pcrs {
        let idx: u8 = k
            .parse()
            .map_err(|_| anyhow::anyhow!("bad pcr index {k:?}"))?;
        values.insert(
            idx,
            decode_pcr_value(val.as_str().ok_or_else(|| anyhow::anyhow!("bad pcr value {k:?}"))?)?,
        );
    }
    Ok(PcrPolicy { values, source })
}

fn collect_nitro(
    device: &PathBuf,
    tcp: &Option<String>,
    nv_index: u32,
    binding_nonce: Option<Vec<u8>>,
    policy: &PcrPolicy,
    user_data: Option<Vec<u8>>,
) -> NitroFacts {
    let mut f = NitroFacts::default();

    let tpm = match tcp {
        Some(addr) => bootproof_tpm::Tpm::connect_swtpm_tcp_started(addr),
        None => bootproof_tpm::Tpm::open_started(device),
    };
    let mut tpm = match tpm {
        Ok(t) => {
            f.device = true;
            t
        }
        Err(e) => {
            f.error = Some(format!("open TPM: {e}"));
            return f;
        }
    };

    let nonce = match binding_nonce {
        Some(n) if n.len() == 32 => n,
        _ => match tpm.get_random(32) {
            Ok(n) => n,
            Err(e) => {
                f.error = Some(format!("TPM2_GetRandom: {e}"));
                return f;
            }
        },
    };

    let doc = match tpm.attestation_document(user_data, Some(nonce.clone()), None, nv_index) {
        Ok(d) => d,
        Err(e) => {
            f.error = Some(format!("attestation_document: {e}"));
            return f;
        }
    };

    if let Ok(pf) = bootproof_tpm::attest::parse_attestation_document(&doc) {
        f.user_data = pf.user_data.clone();
        f.module_id = Some(pf.module_id.clone());
        f.pcr_count = pf.pcrs.len();
        f.region = region_from_certs(&pf.certificate, &pf.cabundle);
        let mut ders = vec![pf.certificate.clone()];
        ders.extend(pf.cabundle.iter().cloned());
        f.chain_cns = ders
            .iter()
            .map(|d| cert_cn(d))
            .filter_map(|o| o)
            .collect();
        let root = bootproof_sdk::format::nitro::aws_nitro_root_ca_der();
        f.root_fp = Some(cert_fingerprint(root));
        f.root_cn = cert_cn(root);
    }

    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let nitro = Nitro::with_pcr_policy(doc, policy.values.clone());
    match nitro.verify(time, &nonce) {
        Ok(_) => {
            f.chain = true;
            f.ok = true;
            f.policy_len = policy.values.len();
            f.policy_source = policy.source.clone();
        }
        Err(e) => f.error = Some(format!("verify: {e}")),
    }
    f
}

/// `/provenance.spdx` evidence: StageX bakes a full SPDX 2.3 build-
/// provenance document (source commit + branch + per-package SHA256
/// digests + dependency graph) into the image root at build time.
#[derive(Debug, Clone, Default)]
struct ProvenanceFacts {
    /// Whether the document is present on this filesystem.
    present: bool,
    doc_name: Option<String>,
    /// `repo @ commit (branch X, dirty N)`.
    origin: Option<String>,
    packages: usize,
    digests: usize,
    relationships: usize,
    error: Option<String>,
}

/// Parse `/provenance.spdx` when present (server-side; the file lives on
/// the machine being attested, not on the verifier).
fn collect_provenance() -> ProvenanceFacts {
    const PATH: &str = "/provenance.spdx";
    let text = match std::fs::read_to_string(PATH) {
        Ok(t) => t,
        Err(_) => return ProvenanceFacts::default(),
    };
    match crate::provenance::parse_spdx(&text) {
        Ok(doc) => ProvenanceFacts {
            present: true,
            doc_name: doc.doc_name.clone(),
            origin: doc.git.display(),
            packages: doc.packages.len(),
            digests: doc.digest_count(),
            relationships: doc.relationships,
            error: None,
        },
        Err(e) => ProvenanceFacts {
            present: true,
            error: Some(e),
            ..Default::default()
        },
    }
}

/// Fetch the SEV-SNP attestation report and parse `snpguest display report`.
fn collect_snp() -> SnpFacts {
    let mut f = SnpFacts {
        present: Path::new("/dev/sev-guest").exists(),
        ..Default::default()
    };
    if !f.present {
        return f;
    }

    let report = Path::new("/tmp/snp_report.bin");
    // Always request a FRESH report: its random report_data (64 bytes,
    // covered by the report signature) is the binding nonce for the TPM
    // document. A stale report would defeat the time-binding.
    let fresh = Path::new("/tmp/snp_report_fresh.bin");
    let req = Path::new("/tmp/snp_req_fresh.bin");
    // snpguest -r generates random report_data and writes it back into the
    // request file; remove any stale files so the randomness is genuinely
    // fresh for this run.
    let _ = std::fs::remove_file(fresh);
    let _ = std::fs::remove_file(req);
    let got_fresh = std::process::Command::new("snpguest")
        .args(["report", "/tmp/snp_report_fresh.bin", "/tmp/snp_req_fresh.bin", "-r"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && fresh.exists()
        && req.exists();
    let report_path = if got_fresh { fresh } else { report };
    if !report_path.exists() {
        return f;
    }

    let out = match std::process::Command::new("snpguest")
        .args(["display", "report"])
        .arg(report_path)
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return f,
    };
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    f.report = true;
    if got_fresh {
        // snpguest writes the 1184-byte firmware report; report_data is the
        // 64 bytes at file offset 0x50, covered by the report signature.
        // snpguest -r also wrote the same 64 bytes into the request file;
        // both must agree and be non-zero (all-zero report_data means the
        // firmware ignored the request, and the binding would be forgeable).
        let raw = std::fs::read(report_path).unwrap_or_default();
        let rreq = std::fs::read(req).unwrap_or_default();
        if raw.len() >= 0x50 + 64 && rreq.len() == 64 && raw[0x50..0x50 + 64] == rreq[..] {
            let rd = &raw[0x50..0x50 + 64];
            if rd.iter().any(|&b| b != 0) {
                f.report_data = Some(rd.to_vec());
            }
        }
    }
    f.cpuid_family = field_value(&text, "CPUID Family ID");
    f.cpuid_model = field_value(&text, "CPUID Model ID");
    f.cpuid_stepping = field_value(&text, "CPUID Stepping");
    f.policy = policy_hex(&text);
    f.smt_allowed = field_bool(&text, "SMT Allowed");
    f.debug_allowed = field_bool(&text, "Debug Allowed");
    f.page_swap_disable = field_bool(&text, "Page Swap Disable");
    f.tsme = field_bool(&text, "TSME Enabled");
    f.ecc = field_bool(&text, "ECC Enabled");
    f.vmpl = field_value(&text, "VMPL");
    f.signing_key = field_value(&text, "signing key");
    f.measurement = hex_block(&text, "Measurement").map(|h| h.get(..32).unwrap_or(&h).to_string());
    f.version = field_value(&text, "Current Version");
    f.tcb_microcode = field_value(&text, "Microcode");

    // Platform-provisioned VLEK certificate + the AMD KDS chain pinned at
    // build time. Full anchor to AMD's root of trust:
    //   VLEK cert (from the PSP) -> ASVK (SEV-VLEK-Milan) -> ARK (ARK-Milan, pinned)
    // then the report signature + TCB fields are checked against that VLEK.
    let certs_dir = PathBuf::from("/tmp/snp_certs");
    let _ = std::fs::create_dir_all(&certs_dir);
    let vlek_pem = certs_dir.join("vlek.pem");
    if std::process::Command::new("snpguest")
        .args(["certificates", "pem"])
        .arg(&certs_dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && vlek_pem.is_file()
    {
        let pem = std::fs::read(&vlek_pem).unwrap_or_default();
        if pem.starts_with(b"-----BEGIN CERTIFICATE-----") {
            if let Some(der) = pem_to_der(&pem) {
                f.vlek_cert_cn = cert_cn(&der);
                f.vlek_cert_not_after = cert_not_after(&der);
            }
            let chain_ok = std::fs::write(certs_dir.join("asvk.pem"), AMD_ASVK_MILAN_PEM).is_ok()
                && std::fs::write(certs_dir.join("ark.pem"), AMD_ARK_MILAN_PEM).is_ok()
                && snpguest_exit_ok(&["verify", "certs"], &[certs_dir.clone()]);
            f.amd_chain_ok = Some(chain_ok);
            f.vlek_verified = Some(snpguest_exit_ok(
                &["verify", "attestation"],
                &[certs_dir.clone(), report_path.to_path_buf()],
            ));
        }
    }
    f
}

/// Query IMDSv2 (token first) for AWS custody facts.
fn collect_imds() -> ImdsFacts {
    let mut f = ImdsFacts::default();
    let token = match imds_token() {
        Some(t) => t,
        None => return f,
    };
    f.region = imds_get(&token, "latest/meta-data/placement/region");
    f.az = imds_get(&token, "latest/meta-data/placement/availability-zone");
    f.instance_id = imds_get(&token, "latest/meta-data/instance-id");
    f.instance_type = imds_get(&token, "latest/meta-data/instance-type");
    f.account = imds_get(&token, "latest/meta-data/iam/info").and_then(|raw| {
        // v2 IMDS answers JSON; older v1 answered a bare ARN.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            return v
                .get("AccountId")
                .and_then(|x| x.as_str())
                .or_else(|| {
                    v.get("Arn")
                        .and_then(|x| x.as_str())
                        .and_then(|arn| arn.split(':').nth(4))
                })
                .map(str::to_string);
        }
        raw.split(':').nth(4).map(str::to_string)
    });
    f.role = imds_get(&token, "latest/meta-data/iam/security-credentials");
    f
}

// ── signed instance identity document (IIDD) ─────────────────────────────────

/// Fetch the PKCS#7-signed instance identity document from IMDS and verify
/// its DSA/SHA-1 signature against the pinned per-region AWS DSA
/// certificate. Only the SIGNED content (embedded in the PKCS#7) is trusted;
/// the plaintext document endpoint is not used at all.
fn collect_iidd(preferred_region: Option<&str>) -> IiddFacts {
    let mut f = IiddFacts::default();
    let token = match imds_token() {
        Some(t) => t,
        None => {
            f.error = Some("IMDS: unreachable".into());
            return f;
        }
    };
    let b64 = match imds_get(&token, "latest/dynamic/instance-identity/pkcs7") {
        Some(b) => b,
        None => {
            f.error = Some("IIDD pkcs7: not exposed by IMDS".into());
            return f;
        }
    };
    use base64::Engine as _;
    let data = match base64::engine::general_purpose::STANDARD
        .decode(b64.replace(|c: char| c.is_whitespace(), ""))
    {
        Ok(d) => d,
        Err(_) => {
            f.error = Some("IIDD pkcs7: bad base64".into());
            return f;
        }
    };
    let (content, digest, canon, sig) = match extract_pkcs7_parts(&data) {
        Some(cs) => cs,
        None => {
            f.error = Some("IIDD pkcs7: unparseable structure".into());
            return f;
        }
    };
    // Try the region pinned by the NitroTPM chain first, then every other
    // pinned region cert.
    let mut order: Vec<(String, &str)> = Vec::new();
    if let Some(pref) = preferred_region {
        if let Some((_, pem)) = IIDD_DSA_CERTS.iter().find(|(r, _)| *r == pref) {
            order.push((pref.to_string(), pem));
        }
    }
    for (r, pem) in IIDD_DSA_CERTS {
        if !order.iter().any(|(o, _)| o == r) {
            order.push((r.to_string(), pem));
        }
    }
    for (cert_region, pem) in order {
        if let Some((p, q, g, y)) = dsa_params(pem) {
            // The signature covers the canonical signed attributes; the
            // content is bound through the (signed) messageDigest attribute.
            let actual: [u8; 20] = sha1::Sha1::digest(&content).into();
            if actual == digest && dsa_verify(&p, &q, &g, &y, &canon, &sig) {
                f.verified = true;
                f.cert_region = Some(cert_region);
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&content) {
                    f.account = v.get("accountId").and_then(|x| x.as_str()).map(str::to_string);
                    f.instance_type = v
                        .get("instanceType")
                        .and_then(|x| x.as_str())
                        .map(str::to_string);
                    f.region = v.get("region").and_then(|x| x.as_str()).map(str::to_string);
                    f.instance_id = v
                        .get("instanceId")
                        .and_then(|x| x.as_str())
                        .map(str::to_string);
                }
                return f;
            }
        }
    }
    f.error = Some(format!(
        "IIDD signature: verified against none of the {} pinned region certs",
        IIDD_DSA_CERTS.len()
    ));
    f
}

/// Read a definite-length DER length; returns (length, header-bytes).
fn der_len(buf: &[u8]) -> Option<(usize, usize)> {
    let l = *buf.first()? as usize;
    if l < 0x80 {
        return Some((l, 1));
    }
    if l == 0x80 {
        return None;
    }
    let n = l & 0x7f;
    if n > 4 || buf.len() < 1 + n {
        return None;
    }
    let mut v = [0u8; 4];
    v[4 - n..].copy_from_slice(&buf[1..1 + n]);
    Some((u32::from_be_bytes(v) as usize, 1 + n))
}

/// Extract from an AWS IIDD PKCS#7 (BER, indefinite length):
/// - the signed content (the definite OCTET STRING in the pkcs7-data
///   contentInfo),
/// - the messageDigest attribute (20 bytes) binding the content,
/// - the canonical signed attributes (SET tag 0x31 + definite length +
///   attribute bytes): the DSA signature covers SHA-1 of THIS, not of the
///   content,
/// - the DSA signature as DER SEQUENCE { r, s } (AWS wraps it in an OCTET
///   STRING rather than the standard BIT STRING).
fn extract_pkcs7_parts(data: &[u8]) -> Option<(Vec<u8>, [u8; 20], Vec<u8>, Vec<u8>)> {
    let oid: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    let i = data.windows(oid.len()).position(|w| w == oid)?;
    let mut j = i + oid.len();
    if data.get(j..j + 2) != Some(&[0xA0, 0x80]) {
        return None;
    }
    j += 2;
    if data.get(j..j + 2) != Some(&[0x24, 0x80]) {
        return None;
    }
    j += 2;
    if data[j] != 0x04 {
        return None;
    }
    j += 1;
    let (len, hdr) = der_len(&data[j..])?;
    j += hdr;
    if j + len > data.len() {
        return None;
    }
    let content = data[j..j + len].to_vec();
    // The DSA signature is the last SEQUENCE in the file whose contents are
    // exactly two INTEGERs (the r/s pair). AWS wraps it in an OCTET STRING
    // rather than the standard BIT STRING, so scan for the shape.
    let n = data.len();
    let mut sig_span: Option<(usize, usize)> = None;
    let mut i = 0;
    while i + 2 < n {
        if data[i] == 0x30 {
            if let Some((len, hdr)) = der_len(&data[i + 1..]) {
                let body = i + 1 + hdr;
                if body + len <= n {
                    let mut k = body;
                    let mut cnt = 0usize;
                    let mut ok = true;
                    while k < body + len && cnt < 2 {
                        if data[k] != 0x02 {
                            ok = false;
                            break;
                        }
                        match der_len(&data[k + 1..]) {
                            Some((il, ih)) => {
                                k += 1 + ih + il;
                                cnt += 1;
                            }
                            None => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok && cnt == 2 && k == body + len {
                        sig_span = Some((i, body + len));
                    }
                }
            }
        }
        i += 1;
    }
    let (ss, se) = sig_span?;
    // Back-walk from the signature SEQUENCE: the wrapping OCTET STRING
    // (`04 <len>`), then digestAlgorithm SEQUENCE { OID dsaWithSHA1 }, then
    // the signedAttrs `a0 <definite length>`.
    if ss < 1 {
        return None;
    }
    let (_, ohdr) = der_len(&data[ss - 1..])?;
    let p = ss - 1 - ohdr;
    if data.get(p) != Some(&0x04) {
        return None;
    }
    let dsa_sha1: &[u8] = &[0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03];
    if p < dsa_sha1.len() || &data[p - dsa_sha1.len()..p] != dsa_sha1 {
        return None;
    }
    let q = p - dsa_sha1.len();
    // The signedAttrs `a0 <definite length>` ends exactly where the
    // digestAlgorithm starts; back-walk to find its tag.
    let mut a0: Option<(usize, usize, usize)> = None;
    let lo = q.saturating_sub(512);
    let mut t = lo;
    while t < q {
        if data[t] == 0xA0 {
            if let Some((alen, ahdr)) = der_len(&data[t + 1..]) {
                if t + 1 + ahdr + alen == q {
                    a0 = Some((t, alen, ahdr));
                }
            }
        }
        t += 1;
    }
    let (q, alen, ahdr) = a0?;
    if q + 1 + ahdr + alen > n {
        return None;
    }
    let mut canon = data[q..q + 1 + ahdr + alen].to_vec();
    canon[0] = 0x31;
    // messageDigest attribute: OID pkcs-9-4, then SET { OCTET STRING 20 }.
    let md_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
    let attrs = &data[q + 1 + ahdr..q + 1 + ahdr + alen];
    let mi = attrs.windows(md_oid.len()).position(|w| w == md_oid)?;
    let mut k = mi + md_oid.len();
    if attrs.get(k..k + 3) != Some(&[0x31, 0x16, 0x04]) || attrs[k + 3] != 0x14 {
        return None;
    }
    k += 4;
    if k + 20 > attrs.len() {
        return None;
    }
    let mut digest = [0u8; 20];
    digest.copy_from_slice(&attrs[k..k + 20]);
    let sig = data[ss..se].to_vec();
    Some((content, digest, canon, sig))
}

/// DSA parameters (p, q, g, y) from a pinned AWS IIDD certificate. The
/// certs are X.509 v1 and x509-parser exposes only `y` for DSA keys, so the
/// parameters are read directly from the raw DER. The SPKI is
/// SEQUENCE { SEQUENCE { OID dsaEncryption, SEQUENCE { INTEGER p, q, g } },
///            BIT STRING { INTEGER y } }; locating the dsaEncryption OID
/// puts the params SEQUENCE immediately after it and the y BIT STRING after
/// that.
fn dsa_params(cert_pem: &str) -> Option<(BigUint, BigUint, BigUint, BigUint)> {
    let der = pem_to_der(cert_pem.as_bytes())?;
    let oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01];
    let i = der.windows(oid.len()).position(|w| w == oid)?;
    let j = i + oid.len();
    if der.get(j) != Some(&0x30) {
        return None;
    }
    let (plen, phdr) = der_len(&der[j + 1..])?;
    let pbody = j + 1 + phdr;
    let pend = pbody + plen;
    if pend > der.len() {
        return None;
    }
    let mut ints: Vec<BigUint> = Vec::new();
    let mut k = pbody;
    while k < pend && ints.len() < 3 {
        if der[k] != 0x02 {
            return None;
        }
        let (il, ih) = der_len(&der[k + 1..])?;
        k += 1 + ih;
        if k + il > pend {
            return None;
        }
        ints.push(BigUint::from_bytes_be(&der[k..k + il]));
        k += il;
    }
    if ints.len() != 3 || k != pend {
        return None;
    }
    if der.get(k) != Some(&0x03) {
        return None;
    }
    let (blen, bhdr) = der_len(&der[k + 1..])?;
    let bbody = k + 1 + bhdr;
    let bend = bbody + blen;
    if bend > der.len() || bbody + 1 > bend || der[bbody] != 0x00 {
        return None;
    }
    let y = der_int(&der[bbody + 1..bend])?;
    Some((ints.remove(0), ints.remove(0), ints.remove(0), y))
}

/// Read one DER INTEGER from a slice that must start with its tag.
fn der_int(buf: &[u8]) -> Option<BigUint> {
    if buf.first() != Some(&0x02) {
        return None;
    }
    let (len, hdr) = der_len(&buf[1..])?;
    let s = 1 + hdr;
    if s + len > buf.len() {
        return None;
    }
    Some(BigUint::from_bytes_be(&buf[s..s + len]))
}

/// DSA signature verification (FIPS 186-4 style): the signature BIT STRING
/// is SEQUENCE { INTEGER r, INTEGER s }; valid iff
/// v = (g^u1 * y^u2 mod p) mod q equals r, with u1 = (SHA1(m) mod q) * s^-1
/// mod q and u2 = r * s^-1 mod q.
fn dsa_verify(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    y: &BigUint,
    content: &[u8],
    sig: &[u8],
) -> bool {
    let mut i = 0;
    if sig.first() == Some(&0x00) {
        i = 1;
    }
    if sig.get(i) != Some(&0x30) {
        return false;
    }
    let (len, hdr) = match der_len(&sig[i + 1..]) {
        Some(x) => x,
        None => return false,
    };
    i += 1 + hdr;
    if i + len > sig.len() {
        return false;
    }
    let mut k = i;
    let mut ints: Vec<BigUint> = Vec::new();
    while k < i + len && ints.len() < 2 {
        if sig[k] != 0x02 {
            return false;
        }
        let (il, ih) = match der_len(&sig[k + 1..]) {
            Some(x) => x,
            None => return false,
        };
        k += 1 + ih;
        if k + il > sig.len() {
            return false;
        }
        ints.push(BigUint::from_bytes_be(&sig[k..k + il]));
        k += il;
    }
    if ints.len() != 2 {
        return false;
    }
    let r = ints[0].clone();
    let s = ints[1].clone();
    if r.is_zero() || s.is_zero() || r >= *q || s >= *q {
        return false;
    }
    // w = s^-1 mod q. q is prime by DSA construction, so Fermat's little
    // theorem gives the inverse (num-bigint 0.4 has no inverse_mod).
    let w = s.modpow(&(q - BigUint::from(2u32)), &q);
    let h = BigUint::from_bytes_be(&sha1::Sha1::digest(content));
    let h_q = h % q;
    let u1 = h_q * &w % q;
    let u2 = &r * w % q;
    let v = (g.modpow(&u1, p) * y.modpow(&u2, p)) % p % q;
    !v.is_zero() && v == r
}

/// Collect guest-local facts (reuse the base `Facts` collector + targeted probes).
fn collect_guest() -> GuestFacts {
    let base = crate::facts::Facts::collect(None);
    let mut f = GuestFacts {
        os: base.os.clone(),
        kernel: base.kernel.clone(),
        cpu_model: base.cpu_model.clone(),
        ..Default::default()
    };

    f.hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string());
    f.mem_total_kb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.trim().trim_end_matches(" kB").parse().ok())
        });

    // UEFI / Secure Boot.
    f.uefi = Path::new("/sys/firmware/efi").exists();
    f.secure_boot = if !f.uefi {
        Some(false)
    } else if Path::new("/sys/firmware/efi/sb").exists() {
        Some(true)
    } else {
        None
    };

    // LUKS / device-mapper.
    f.luks = Path::new("/sys/fs/cryptsetup").exists();
    f.dm0_crypt = std::fs::read_to_string("/sys/block/dm-0/dm/table")
        .ok()
        .map(|t| t.starts_with("0 0 crypt"));

    // CPU hardening flags.
    let flags = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("flags")).map(str::to_string))
        .unwrap_or_default();
    f.smap = flags.contains("smap");
    f.smep = flags.contains("smep");
    f.ibpb = flags.contains("ibpb");
    f.stibp = flags.contains("stibp");
    f.rdrand = flags.contains("rdrand");
    f.rdseed = flags.contains("rdseed");

    // Hardware RNG.
    f.hwrng = Path::new("/dev/hwrng").exists();

    // NIC driver + vendor.
    f.nic_driver = std::fs::read_link("/sys/class/net/eth0/device/driver")
        .ok()
        .and_then(|p| p.file_name().map(|x| x.to_string_lossy().to_string()));
    f.nic_vendor = std::fs::read_to_string("/sys/class/net/eth0/device/vendor")
        .ok()
        .map(|s| s.trim().to_string());

    // IOMMU.
    f.iommu = Path::new("/sys/kernel/iommu_groups").exists();

    // Kernel hardening options (best-effort; gzip -dc /proc/config.gz).
    f.kernel_hardening = kernel_hardening_options();

    // Administrative-access signals.
    f.uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
        });
    f.sshd = Path::new("/etc/ssh/sshd_config").exists() || process_running("sshd");
    f.serial_console = std::fs::read_to_string("/proc/cmdline")
        .map(|c| c.contains("console=ttyS"))
        .unwrap_or(false);
    f.luks_tpm_bound = std::fs::read_to_string("/sys/block/dm-0/dm/name")
        .ok()
        .is_some_and(|n| n.trim().to_lowercase().contains("crypt"))
        && std::fs::read_to_string("/sys/block/dm-0/dm/table")
            .map(|t| t.to_lowercase().contains("tpm2") || t.starts_with("0 0 crypt"))
            .unwrap_or(false);
    f
}

// ── gatherer helpers ──────────────────────────────────────────────────────────

/// IMDSv2 token (PUT /latest/api/token with ttl 60s).
fn imds_token() -> Option<String> {
    imds_http(
        "PUT",
        "latest/api/token",
        Some("X-aws-ec2-metadata-token-ttl-seconds: 60"),
    )
}

/// IMDSv2 GET with the token header.
fn imds_get(token: &str, path: &str) -> Option<String> {
    imds_http("GET", path, Some(&format!("X-aws-ec2-metadata-token: {token}")))
}

/// Raw-socket HTTP request to IMDS (169.254.169.254:80).
fn imds_http(method: &str, path: &str, extra_header: Option<&str>) -> Option<String> {
    let addr: std::net::SocketAddr = "169.254.169.254:80".parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))
        .ok()?;
    let mut req = format!("{method} http://169.254.169.254/{path} HTTP/1.1\r\nHost: 169.254.169.254\r\n");
    if let Some(h) = extra_header {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    if s.read_to_end(&mut buf).is_err() {
        return None;
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text.lines().next()?.split_whitespace().nth(1)?;
    if status != "200" {
        return None;
    }
    let body = text.split("\r\n\r\n").nth(1)?.trim().to_string();
    if body.is_empty() {
        None
    } else {
        Some(body)
    }
}

/// Is a process with exactly this `/proc/[pid]/comm` currently running?
/// In-process equivalent of `pgrep -x <name>` (no external binary).
fn process_running(name: &str) -> bool {
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(s) = fname.to_str() else { continue };
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm = std::fs::read_to_string(entry.path().join("comm")).ok();
        if comm.as_deref().map(|c| c.trim() == name).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Key kernel hardening options from /proc/config.gz (name, enabled).
fn kernel_hardening_options() -> Option<Vec<(String, bool)>> {
    use std::io::Read;
    let file = std::fs::File::open("/proc/config.gz").ok()?;
    let mut dec = flate2::read::GzDecoder::new(file);
    let mut s = String::new();
    dec.read_to_string(&mut s).ok()?;
    let wanted = [
        "CONFIG_RANDOMIZE_MEMORY",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_STRICT_DEVMEM",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        "CONFIG_INIT_ON_FREE_DEFAULT_ON",
        "CONFIG_HARDENED_USERCOPY",
    ];
    Some(
        wanted
            .iter()
            .map(|w| {
                let enabled = s
                    .lines()
                    .any(|l| l.trim() == &format!("{w}=y"));
                (w.to_string(), enabled)
            })
            .collect(),
    )
}

/// Extract the region (e.g. "us-east-2") from the leaf cert + CA bundle CNs.
fn region_from_certs(cert: &[u8], cabundle: &[Vec<u8>]) -> Option<String> {
    let mut all: Vec<&[u8]> = Vec::new();
    if !cert.is_empty() {
        all.push(cert);
    }
    for c in cabundle {
        all.push(c);
    }
    for c in &all {
        if let Ok((_, x)) = x509_parser::certificate::X509Certificate::from_der(c) {
            if let Some(cn) = x.subject().iter_common_name().next()
                && let Ok(cn_str) = cn.as_str()
            {
                if let Some(r) = region_from_cn(cn_str) {
                    return Some(r);
                }
            }
        }
    }
    None
}

/// Subject Common Name of a DER certificate, if parseable.
fn cert_cn(der: &[u8]) -> Option<String> {
    let (_, x) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let cn = x.subject().iter_common_name().next()?;
    cn.as_str().ok().map(|s| s.to_string())
}

/// SHA-256 fingerprint of a DER cert as compact lowercase hex (no colons;
/// 64 chars fits an 80-column line).
fn cert_fingerprint(der: &[u8]) -> String {
    let digest = sha2::Sha256::digest(der);
    let mut s = String::new();
    for b in digest.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Extract the DER of the first certificate from a PEM blob.
fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// notAfter of a DER cert as a UTC string (best-effort).
fn cert_not_after(der: &[u8]) -> Option<String> {
    let (_, x) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let ta = x.validity().not_after;
    Some(format!("{ta}"))
}

/// Run snpguest with the given args; true on exit 0.
fn snpguest_exit_ok(args: &[&str], paths: &[PathBuf]) -> bool {
    let mut cmd = std::process::Command::new("snpguest");
    cmd.args(args);
    for p in paths {
        cmd.arg(p);
    }
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

/// Find an AWS-region-looking token (e.g. "us-east-2") in a CN string.
fn region_from_cn(cn: &str) -> Option<String> {
    cn.split('.').find_map(|t| {
        if is_region_token(t) {
            Some(t.to_string())
        } else {
            None
        }
    })
}

/// Does this dotted token look like an AWS region (`xx-[a-z]+(-[a-z]+)*-N`)?
fn is_region_token(t: &str) -> bool {
    let b = t.as_bytes();
    if b.len() < 6 {
        return false;
    }
    if !b[0].is_ascii_lowercase() || !b[1].is_ascii_lowercase() {
        return false;
    }
    if b[2] != b'-' {
        return false;
    }
    if !b[b.len() - 1].is_ascii_digit() {
        return false;
    }
    if t.contains("--") {
        return false;
    }
    // Middle (between the first "-xx" and the trailing digit) is letters or "-".
    b[3..b.len() - 1].iter().all(|c| c.is_ascii_lowercase() || *c == b'-')
}

// ── snpguest display text parsing ─────────────────────────────────────────────

/// Value of the first line whose trimmed form starts with `key`, after the colon.
fn field_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix(key) {
            let v = v.trim_start();
            if let Some(v) = v.strip_prefix(':') {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Boolean value of `field_value` (true/false), else None.
fn field_bool(text: &str, key: &str) -> Option<bool> {
    field_value(text, key).and_then(|v| match v.to_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

/// The guest-policy hex from the "Guest Policy (0x...):" line.
fn policy_hex(text: &str) -> Option<String> {
    for line in text.lines() {
        if line.trim().starts_with("Guest Policy") {
            let t = line.trim();
            let start = t.find("0x")?;
            let rest = &t[start + 2..];
            let end = rest
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(rest.len());
            let hex = &rest[..end];
            if !hex.is_empty() {
                return Some(hex.to_string());
            }
        }
    }
    None
}

/// Concatenated lowercase hex of the block of hex lines following `header:`.
fn hex_block(text: &str, header: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|l| {
        let t = l.trim();
        t == header || t == format!("{header}:")
    })?;
    let mut hex = String::new();
    for line in &lines[start + 1..] {
        let t = line.trim();
        if t.is_empty() {
            break;
        }
        let ok = t
            .split_whitespace()
            .all(|w| w.len() == 2 && w.bytes().all(|c| c.is_ascii_hexdigit()));
        if !ok {
            break;
        }
        hex.push_str(t.replace(" ", "").to_lowercase().as_str());
    }
    if hex.is_empty() {
        None
    } else {
        Some(hex)
    }
}

// ── build the tree ────────────────────────────────────────────────────────────

/// Assemble the branches from the gathered evidence.
///
/// Order: Cryptography, Custody, Security, Access, Hardware, Software,
/// Provenance (last, only when /provenance.spdx is present). Test-only
/// convenience: production paths call `build_tree_with` with a real
/// provenance document.
#[cfg(test)]
fn build_tree(
    nitro: NitroFacts,
    snp: SnpFacts,
    imds: ImdsFacts,
    iidd: IiddFacts,
    guest: GuestFacts,
) -> TrustTree {
    build_tree_with(nitro, snp, imds, iidd, guest, &ProvenanceFacts::default())
}

/// Same as `build_tree` with an explicit provenance document.
fn build_tree_with(
    nitro: NitroFacts,
    snp: SnpFacts,
    imds: ImdsFacts,
    iidd: IiddFacts,
    guest: GuestFacts,
    prov: &ProvenanceFacts,
) -> TrustTree {
    let mut branches = vec![
        crypto_branch(&nitro, &snp),
        custody_branch(&nitro, &snp, &imds, &iidd, &guest),
        security_branch(&nitro, &snp, &imds, &guest),
        access_branch(&imds, &guest),
        hardware_branch(&nitro, &snp, &guest),
        software_branch(&nitro, &snp, &guest),
    ];
    if let Some(pb) = provenance_branch(prov) {
        branches.push(pb);
    }
    TrustTree { branches }
}

/// Provenance branch: the image-baked SPDX build-provenance document.
/// The document is self-reported (the build wrote it) -> `unknown` until
/// its digests are checked against published signatures
/// (`bootproof provenance --sigs <repo> --keyring <pgp>`) or a local
/// rebuild at the pinned commit reproduces them.
fn provenance_branch(prov: &ProvenanceFacts) -> Option<Branch> {
    if !prov.present {
        return None;
    }
    let (verdict, value, ev) = if let Some(e) = &prov.error {
        (
            Verdict::Unknown,
            "present, unparseable".to_string(),
            vec![Evidence {
                source: "spdx".into(),
                detail: format!("parse error: {e}"),
                proof: Verdict::Unknown,
            }],
        )
    } else {
        let mut ev = Vec::new();
        if let Some(n) = &prov.doc_name {
            ev.push(Evidence {
                source: "spdx".into(),
                detail: format!("document: {n}"),
                proof: Verdict::Likely,
            });
        }
        if let Some(o) = &prov.origin {
            ev.push(Evidence {
                source: "spdx".into(),
                detail: format!("source origin: {o} (self-declared by the build)"),
                proof: Verdict::Likely,
            });
        }
        ev.push(Evidence {
            source: "spdx".into(),
            detail: format!(
                "{} packages, {} SHA256 digests, {} dependency edges",
                prov.packages, prov.digests, prov.relationships
            ),
            proof: Verdict::Likely,
        });
        ev.push(Evidence {
            source: "spdx".into(),
            detail: "document is baked into the image by the build (self-reported); digests are not checked here".into(),
            proof: Verdict::Unknown,
        });
        ev.push(Evidence {
            source: "spdx".into(),
            detail: "close the gap: `bootproof provenance --sigs <signatures-repo> --keyring <pgp>` (published sigs), or rebuild locally at the pinned commit, regenerate with `python3 src/provenance.py <target> --raw`, and diff with `--compare`".into(),
            proof: Verdict::Unknown,
        });
        (
            Verdict::Unknown,
            format!("SPDX 2.3, {} digests", prov.digests),
            ev,
        )
    };
    Some(Branch {
        name: "Provenance".into(),
        facts: vec![Fact {
            name: "Source / Provenance".into(),
            value,
            verdict,
            evidence: ev,
        }],
    })
}

/// The "Attestation Level" fact: L0 software TPM, L1 hardware TPM, L2 CVM
/// dual attestation, L3 ring isolation (reserved). Derived from the pinned
/// roots that verified, never from guest claims.
fn attestation_level_fact(nitro: &NitroFacts, snp: &SnpFacts) -> Fact {
    let level = TrustLevel::derive(nitro, snp, nitro.device);
    let (value, verdict, evidence) = match level {
        TrustLevel::L3 => (
            "L3: ring isolation (SVSM)".to_string(),
            Verdict::True,
            vec![Evidence {
                source: "svsm".into(),
                detail: "SVSM attestation verified from a ring the hypervisor cannot reach".into(),
                proof: Verdict::True,
            }],
        ),
        TrustLevel::L2 => (
            "L2: CVM dual attestation (hardware TPM + SEV-SNP, cross-bound)".to_string(),
            Verdict::True,
            vec![
                Evidence {
                    source: "nitro-tpm".into(),
                    detail: "TPM attestation chain verified to the pinned AWS Nitro Enclaves root (ES384 + chain + nonce)".into(),
                    proof: Verdict::True,
                },
                Evidence {
                    source: "sev-snp".into(),
                    detail: "SEV-SNP report signature + TCB verified to the AMD ARK via the platform-provisioned VLEK".into(),
                    proof: Verdict::True,
                },
                Evidence {
                    source: "note".into(),
                    detail: "a fresh 32-byte nonce sits in BOTH signed artifacts: the TPM and the CVM are the same run".into(),
                    proof: Verdict::True,
                },
            ],
        ),
        TrustLevel::L1 => (
            "L1: hardware TPM (pinned vendor root)".to_string(),
            Verdict::True,
            vec![
                Evidence {
                    source: "nitro-tpm".into(),
                    detail: "TPM attestation chain verified to the pinned AWS Nitro Enclaves root (ES384 + chain + nonce)".into(),
                    proof: Verdict::True,
                },
                Evidence {
                    source: "note".into(),
                    detail: "no CPU-attested report anchored (SEV-SNP/TDX), so L2 dual attestation is not established".into(),
                    proof: Verdict::Likely,
                },
            ],
        ),
        TrustLevel::L0 => (
            "L0: software/unproven TPM2 (no pinned vendor root)".to_string(),
            Verdict::Likely,
            vec![
                Evidence {
                    source: "tpm".into(),
                    detail: "a TPM2 interface responds, but its attestation did not verify to a pinned hardware vendor root".into(),
                    proof: Verdict::Likely,
                },
                Evidence {
                    source: "note".into(),
                    detail: nitro
                        .error
                        .clone()
                        .unwrap_or_else(|| "software TPM (swtpm), or vendor hardware whose root is not pinned in this binary".into()),
                    proof: Verdict::Unknown,
                },
            ],
        ),
        TrustLevel::None => (
            "none: no TPM2 interface".to_string(),
            Verdict::False,
            vec![Evidence {
                source: "tpm".into(),
                detail: format!(
                    "no TPM2 device or bridge endpoint: {}",
                    nitro.error.clone().unwrap_or_else(|| "open failed".into())
                ),
                proof: Verdict::False,
            }],
        ),
    };
    Fact {
        name: "Attestation Level".into(),
        value,
        verdict,
        evidence,
    }
}

fn crypto_branch(nitro: &NitroFacts, snp: &SnpFacts) -> Branch {
    let level_fact = attestation_level_fact(nitro, snp);
    let binding_fact = if nitro.ok && snp.report && snp.report_data.is_some() {
        let nonce_hex: String = snp
            .report_data
            .as_ref()
            .and_then(|rd| rd.get(..8))
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
            .unwrap_or_default();
        Fact {
            name: "Cross-Attestation Binding".into(),
            value: "TPM + SEV-SNP bound by shared nonce".into(),
            verdict: Verdict::True,
            evidence: vec![
                Evidence {
                    source: "nitro-tpm".into(),
                    detail: format!(
                        "signed NitroTPM document echoes nonce {nonce_hex}… (nonce echo verified against the pinned AWS root)"
                    ),
                    proof: Verdict::True,
                },
                Evidence {
                    source: "sev-snp".into(),
                    detail: "signed SEV-SNP report carries the same nonce in its \
                             report_data field (signature covers it; anchored to the \
                             AMD root)"
                        .into(),
                    proof: Verdict::True,
                },
                Evidence {
                    source: "note".into(),
                    detail: "both attestations were signed after the nonce was \
                            created, on this system, in this run; artifacts from \
                            different machines or times cannot be spliced"
                        .into(),
                    proof: Verdict::True,
                },
            ],
        }
    } else {
        Fact {
            name: "Cross-Attestation Binding".into(),
            value: "unknown".into(),
            verdict: Verdict::Unknown,
            evidence: vec![
                Evidence {
                    source: "note".into(),
                    detail: "no fresh SEV-SNP report with report_data was obtained, \
                            or the NitroTPM attestation did not verify; the TPM nonce \
                            could not be derived from a fresh signed report"
                        .into(),
                    proof: Verdict::Unknown,
                },
            ],
        }
    };

    Branch {
        name: "Cryptography".into(),
        facts: vec![
            level_fact,
            Fact {
                name: "Ephemeral Key".into(),
                value: "N/A".into(),
                verdict: Verdict::Unknown,
                evidence: vec![Evidence {
                    source: "key-wrapping".into(),
                    detail: "Encrypt a secret to a short-lived key; not yet wired."
                        .into(),
                    proof: Verdict::Unknown,
                }],
            },
            Fact {
                name: "System Key".into(),
                value: "N/A".into(),
                verdict: Verdict::Unknown,
                evidence: vec![Evidence {
                    source: "key-wrapping".into(),
                    detail: "Encrypt a secret to a persistent key locked to this system; not yet wired."
                        .into(),
                    proof: Verdict::Unknown,
                }],
            },
            Fact {
                name: "User Key".into(),
                value: "N/A".into(),
                verdict: Verdict::Unknown,
                evidence: vec![Evidence {
                    source: "key-wrapping".into(),
                    detail: "Encrypt to the active User Key; recoverable by m-of-n user shares; not yet wired."
                        .into(),
                    proof: Verdict::Unknown,
                }],
            },
            Fact {
                name: "Provider Key".into(),
                value: "N/A".into(),
                verdict: Verdict::Unknown,
                evidence: vec![Evidence {
                    source: "key-wrapping".into(),
                    detail: "Encrypt to the active Provider Key; recoverable by m-of-n provider shares; not yet wired."
                        .into(),
                    proof: Verdict::Unknown,
                }],
            },
            binding_fact,
        ],
    }
}

/// Who owns / controls this system, and the hardware custody chain.
fn custody_branch(
    nitro: &NitroFacts,
    snp: &SnpFacts,
    imds: &ImdsFacts,
    iidd: &IiddFacts,
    guest: &GuestFacts,
) -> Branch {
    // Owner / Account — `true` when the signed IIDD attests the account.
    let (own_verdict, own_value, own_ev) = if iidd.verified {
        let acc = iidd
            .account
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let cr = iidd
            .cert_region
            .clone()
            .unwrap_or_else(|| "region".to_string());
        let mut ev = vec![Evidence {
            source: "imds".into(),
            detail: format!(
                "signed instance identity document: accountId {acc} (DSA/SHA-1 \
                 PKCS#7 verified against the pinned AWS {cr} DSA certificate)"
            ),
            proof: Verdict::True,
        }];
        if let Some(acc2) = &imds.account {
            if acc2 != &acc {
                ev.push(Evidence {
                    source: "imds".into(),
                    detail: format!(
                        "MISMATCH: IAM instance-profile ARN shows account {acc2}, signed IIDD shows {acc}"
                    ),
                    proof: Verdict::False,
                });
            }
        }
        if let Some(mid) = &nitro.module_id {
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!(
                    "NitroTPM module {mid} — hardware custodied by the provider, signed to the AWS Nitro Enclaves root"
                ),
                proof: Verdict::True,
            });
        }
        (Verdict::True, format!("AWS account {acc}"), ev)
    } else if let Some(acc) = &imds.account {
        let mut ev = vec![Evidence {
            source: "imds".into(),
            detail: format!("IAM instance-profile ARN under account {acc}"),
            proof: Verdict::Likely,
        }];
        if let Some(mid) = &nitro.module_id {
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!(
                    "NitroTPM module {mid} — hardware custodied by the provider, signed to the AWS Nitro Enclaves root"
                ),
                proof: Verdict::True,
            });
        }
        (Verdict::Likely, format!("AWS account {acc}"), ev)
    } else if nitro.ok {
        (
            Verdict::Likely,
            "AWS (account not exposed to guest)".to_string(),
            vec![Evidence {
                source: "nitro-tpm".into(),
                detail: "NitroTPM verified to the AWS root; account ARN not exposed to this guest"
                    .into(),
                proof: Verdict::Likely,
            }],
        )
    } else {
        (Verdict::Unknown, "unknown".to_string(), vec![])
    };

    // Instance identity.
    let (inst_verdict, inst_value, inst_ev) = if let Some(id) = &imds.instance_id {
        let mut ev = Vec::new();
        if let Some(mid) = &nitro.module_id {
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!(
                    "signed NitroTPM module id embeds the instance id ({mid})"
                ),
                proof: Verdict::True,
            });
        }
        ev.push(Evidence {
            source: "imds".into(),
            detail: match &imds.instance_type {
                Some(t) => format!("instance-id {id}, type {t}"),
                None => format!("instance-id {id} (type not exposed to this guest)"),
            },
            proof: Verdict::Likely,
        });
        if iidd.verified {
            if let Some(t) = &iidd.instance_type {
                ev.push(Evidence {
                    source: "imds".into(),
                    detail: format!(
                        "signed instance identity document: instanceType {t} (DSA/SHA-1 PKCS#7 verified against the pinned AWS cert)"
                    ),
                    proof: Verdict::True,
                });
            }
        }
        if let Some(h) = &guest.hostname {
            ev.push(Evidence {
                source: "sysfs".into(),
                detail: format!("hostname {h} (cross-anchors the region)"),
                proof: Verdict::Likely,
            });
        }
        let v = if ev.iter().any(|e| e.proof == Verdict::True) {
            Verdict::True
        } else {
            Verdict::Likely
        };
        let value = match iidd.instance_type.as_ref().or(imds.instance_type.as_ref()) {
            Some(t) => format!("{id} ({t})"),
            None => id.clone(),
        };
        (v, value, ev)
    } else {
        (Verdict::Unknown, "unknown".to_string(), vec![])
    };

    // Location (region + AZ), proven by the cert chain.
    let (loc_verdict, loc_value, loc_ev) = if let Some(r) = &nitro.region {
        let mut ev = vec![Evidence {
            source: "nitro-tpm".into(),
            detail: format!("region {r} in the NitroTPM certificate chain CNs (proven)"),
            proof: Verdict::True,
        }];
        if let Some(az) = &imds.az {
            ev.push(Evidence {
                source: "imds".into(),
                detail: format!("availability-zone {az}"),
                proof: Verdict::Likely,
            });
        }
        if let Some(ir) = &imds.region {
            ev.push(Evidence {
                source: "imds".into(),
                detail: format!("placement/region = {ir} (cross-anchored)"),
                proof: Verdict::Likely,
            });
        }
        if iidd.verified {
            if let Some(sr) = &iidd.region {
                ev.push(Evidence {
                    source: "imds".into(),
                    detail: format!(
                        "signed instance identity document: region {sr} (DSA/SHA-1 PKCS#7 verified against the pinned AWS cert)"
                    ),
                    proof: Verdict::True,
                });
            }
        }
        (
            Verdict::True,
            match &imds.az {
                Some(az) => format!("AWS {r} ({az})"),
                None => format!("AWS {r}"),
            },
            ev,
        )
    } else if let Some(ir) = &imds.region {
        (
            Verdict::Likely,
            format!("AWS {ir}"),
            vec![Evidence {
                source: "imds".into(),
                detail: format!("placement/region = {ir}"),
                proof: Verdict::Likely,
            }],
        )
    } else {
        (Verdict::Unknown, "unknown".to_string(), vec![])
    };

    // Custody chain (the hardware path of control).
    let mut chain_ev = Vec::new();
    if nitro.ok {
        chain_ev.push(Evidence {
            source: "nitro-tpm".into(),
            detail: "NitroTPM attestation verified to the AWS Nitro Enclaves root (ES384 signature + chain + nonce)"
                .into(),
            proof: Verdict::True,
        });
    }
    if snp.report {
        chain_ev.push(Evidence {
            source: "sev-snp".into(),
            detail: "AMD SEV-SNP secure enclave: per-VM memory encryption + isolation, CPU-attested report"
                .into(),
            proof: Verdict::True,
        });
    }
    chain_ev.push(Evidence {
        source: "note".into(),
        detail: "physical custody is the provider's datacenter; the guest cannot verify the facility itself"
            .into(),
        proof: Verdict::Likely,
    });
    let chain_value = if nitro.ok && snp.report {
        "AWS datacenter → Nitro → NitroTPM → SEV-SNP (AMD)".to_string()
    } else if nitro.ok {
        "AWS datacenter → Nitro → NitroTPM".to_string()
    } else {
        "unknown".to_string()
    };
    let chain_verdict = if chain_ev.iter().any(|e| e.proof == Verdict::True) {
        Verdict::Likely
    } else {
        Verdict::Unknown
    };

    Branch {
        name: "Custody".into(),
        facts: vec![
            Fact {
                name: "Owner / Account".into(),
                value: own_value,
                verdict: own_verdict,
                evidence: own_ev,
            },
            Fact {
                name: "Instance".into(),
                value: inst_value,
                verdict: inst_verdict,
                evidence: inst_ev,
            },
            Fact {
                name: "Location".into(),
                value: loc_value,
                verdict: loc_verdict,
                evidence: loc_ev,
            },
            Fact {
                name: "Custody Chain".into(),
                value: chain_value,
                verdict: chain_verdict,
                evidence: chain_ev,
            },
        ],
    }
}

/// Whether administrative (or administrative-equivalent) access is available.
fn access_branch(imds: &ImdsFacts, guest: &GuestFacts) -> Branch {
    let mut ev = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    if let Some(role) = &imds.role {
        ev.push(Evidence {
            source: "imds".into(),
            detail: format!(
                "cloud API access via IAM role {role} (policy not resolvable from the guest)"
            ),
            proof: Verdict::Likely,
        });
        paths.push(format!("IAM role {role}"));
    }
    if guest.uid == Some(0) {
        ev.push(Evidence {
            source: "sysfs".into(),
            detail: "local root (uid 0) — this process runs as root".into(),
            proof: Verdict::True,
        });
        paths.push("local root".into());
    }
    if guest.sshd {
        ev.push(Evidence {
            source: "sysfs".into(),
            detail: "SSH server present (remote admin path)".into(),
            proof: Verdict::Likely,
        });
        paths.push("SSH".into());
    }
    if guest.serial_console {
        ev.push(Evidence {
            source: "sysfs".into(),
            detail: "serial console enabled in the kernel cmdline (console=ttyS)".into(),
            proof: Verdict::Likely,
        });
        paths.push("serial console".into());
    }

    let (verdict, value) = if paths.is_empty() {
        ev.push(Evidence {
            source: "note".into(),
            detail: "no IAM role, local root, SSH, or serial console detected".into(),
            proof: Verdict::Unknown,
        });
        (Verdict::Unknown, "no admin paths observed".to_string())
    } else {
        (Verdict::Likely, paths.join(" + "))
    };

    Branch {
        name: "Access".into(),
        facts: vec![Fact {
            name: "Administrative Access".into(),
            value,
            verdict,
            evidence: ev,
        }],
    }
}

/// Anchor evidence for the SEV-SNP facts: how far the report is anchored,
/// plus (when AMD-anchored) the full VLEK certificate chain.
fn amd_anchor_ev(snp: &SnpFacts) -> Vec<Evidence> {
    if snp.amd_anchored() {
        let ark_fp = pem_to_der(AMD_ARK_MILAN_PEM)
            .as_deref()
            .map(cert_fingerprint)
            .unwrap_or_else(|| "unknown".into());
        let cn = snp.vlek_cert_cn.clone().unwrap_or_else(|| "SEV-VLEK".into());
        let exp = snp
            .vlek_cert_not_after
            .clone()
            .unwrap_or_else(|| "?".into());
        vec![
            Evidence {
                source: "sev-snp".into(),
                detail: "report signature verified: 'VEK signed the Attestation Report'; TCB fields (bl/tee/snp/ucode) matched the VLEK certificate".into(),
                proof: Verdict::True,
            },
            Evidence {
                source: "sev-snp".into(),
                detail: format!(
                    "VLEK certificate CN={cn} (ECDSA P-384, valid to {exp}) \u{2190} ASVK (SEV-VLEK-Milan) \u{2190} ARK (ARK-Milan, SHA-256 {ark_fp}, pinned at build time)"
                ),
                proof: Verdict::True,
            },
            Evidence {
                source: "note".into(),
                detail: "the VLEK certificate is provisioned by the AMD PSP; ASVK+ARK are pinned in this binary from AMD KDS (kdsintf.amd.com). A malicious platform cannot forge the report signature or the certificate chain without AMD's keys".into(),
                proof: Verdict::True,
            },
        ]
    } else if snp.vlek_verified == Some(true) {
        vec![Evidence {
            source: "note".into(),
            detail: "report signature verified against the platform VLEK, but the VLEK certificate -> ASVK -> ARK chain was not verified; not anchored to AMD's root"
                .into(),
            proof: Verdict::Likely,
        }]
    } else {
        vec![Evidence {
            source: "note".into(),
            detail: "not anchored to AMD's root: VLEK certificate/chain unavailable; a malicious platform could serve a forged report"
                .into(),
            proof: Verdict::Likely,
        }]
    }
}

fn security_branch(
    nitro: &NitroFacts,
    snp: &SnpFacts,
    imds: &ImdsFacts,
    guest: &GuestFacts,
) -> Branch {
    // AMD-root anchoring of the SEV-SNP report:
    //   report signature + TCB fields verified against the platform VLEK,
    //   VLEK certificate chains to the pinned ARK-Milan via ASVK.
    let anchored = snp.amd_anchored();
    let snp_proof = if anchored { Verdict::True } else { Verdict::Likely };
    let snp_tag = if anchored { "AMD-root-anchored" } else { "platform-anchored" };

    // 1. Memory Encryption.
    let mem_enc = if snp.report {
        let mut ev = vec![Evidence {
            source: "sev-snp".into(),
            detail: format!(
                "SEV-SNP VM; TSME {} (whole-memory encryption); per-VM unique key; guest policy 0x{}",
                bool_str(snp.tsme),
                snp.policy.as_deref().unwrap_or("?"),
            ),
            proof: snp_proof,
        }];
        if let Some(k) = &snp.signing_key {
            ev.push(Evidence {
                source: "sev-snp".into(),
                detail: format!("report signed with {k}; ECC {}", bool_str(snp.ecc)),
                proof: snp_proof,
            });
        }
        if let Some(v) = &snp.version {
            ev.push(Evidence {
                source: "sev-snp".into(),
                detail: format!(
                    "SNP firmware {v} (TCB microcode {})",
                    snp.tcb_microcode.as_deref().unwrap_or("?")
                ),
                proof: snp_proof,
            });
        }
        ev.extend(amd_anchor_ev(snp));
        (
            snp_proof,
            format!("SEV-SNP per-VM key + TSME ({snp_tag})"),
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "no SEV-SNP report".to_string(),
            vec![Evidence {
                source: "sev-snp".into(),
                detail: "no SEV-SNP attestation report available".into(),
                proof: Verdict::Unknown,
            }],
        )
    };

    // 2. Filesystem Encryption.
    let fs_enc = if guest.luks || guest.dm0_crypt == Some(true) {
        if guest.luks_tpm_bound {
            let ev = vec![
                Evidence {
                    source: "sysfs".into(),
                    detail: "dm-crypt/LUKS device whose key the TPM releases (TPM2-bound) — kernel self-reported via sysfs".into(),
                    proof: Verdict::Likely,
                },
                Evidence {
                    source: "tpm-pcr".into(),
                    detail: format!(
                        "key released only when measured boot state matches the bound PCRs: {}",
                        pcr_binding_note()
                    ),
                    proof: Verdict::Likely,
                },
            ];
            (Verdict::Likely, "Hardware locked (TPM)".to_string(), ev)
        } else {
            (
                Verdict::Likely,
                "guest block-layer LUKS".to_string(),
                vec![Evidence {
                    source: "sysfs".into(),
                    detail: "LUKS/dm-crypt block device present in the guest (kernel self-reported via sysfs; key not observed as TPM-bound)".into(),
                    proof: Verdict::Likely,
                }],
            )
        }
    } else {
        (
            Verdict::Unknown,
            "none observed in guest".to_string(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: format!(
                    "no cryptsetup device registered; dm-0 table {} ",
                    match guest.dm0_crypt {
                        Some(true) => "is crypt",
                        Some(false) => "is not crypt",
                        None => "not exposed to guest",
                    }
                ),
                proof: Verdict::Unknown,
            }, Evidence {
                source: "aws".into(),
                detail: "EBS/KMS server-side (at-rest) encryption not verifiable from the guest"
                    .into(),
                proof: Verdict::Unknown,
            }],
        )
    };

    // 3. Memory Isolation.
    let mem_iso = if snp.report {
        let debug_off = snp.debug_allowed == Some(false);
        let swap_disabled = snp.page_swap_disable == Some(true);
        let verdict = if debug_off && swap_disabled {
            snp_proof
        } else {
            Verdict::Unknown
        };
        let mut ev = vec![Evidence {
            source: "sev-snp".into(),
            detail: format!(
                "SEV-SNP ASID isolation; SMT Allowed={}; Debug Allowed={}; Page Swap Disable={}",
                bool_opt(snp.smt_allowed),
                bool_opt(snp.debug_allowed),
                bool_opt(snp.page_swap_disable),
            ),
            proof: verdict,
        }];
        if debug_off && swap_disabled {
            ev.extend(amd_anchor_ev(snp));
        }
        (
            verdict,
            format!("SEV-SNP ASID + debug off ({snp_tag})"),
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "no SEV-SNP report".to_string(),
            vec![],
        )
    };

    // 4. Secure Boot.
    let (sb_verdict, sb_value, sb_ev) = match guest.secure_boot {
        Some(true) => (
            Verdict::Likely,
            "active (kernel self-reported)".to_string(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: "/sys/firmware/efi/sb present (kernel self-reported; a malicious kernel could hide its absence)".into(),
                proof: Verdict::Likely,
            }],
        ),
        Some(false) => (
            Verdict::False,
            "no UEFI".to_string(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: "no UEFI firmware (Secure Boot not applicable)".into(),
                proof: Verdict::True,
            }],
        ),
        None => (
            Verdict::Unknown,
            "not exposed to guest".to_string(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: "UEFI active but /sys/firmware/efi/sb not exposed; cannot determine".into(),
                proof: Verdict::Unknown,
            }],
        ),
    };

    // 5. Hardened Kernel.
    let flags_present = [guest.smap, guest.smep, guest.ibpb, guest.stibp]
        .iter()
        .filter(|b| **b)
        .count();
    let (hk_verdict, hk_value, hk_ev) = if flags_present == 4 {
        let verdict = Verdict::Likely;
        let mut ev = vec![Evidence {
            source: "sysfs".into(),
            detail: "SMAP + SMEP + IBPB + STIBP CPU mitigations present (kernel self-reported via /proc/cpuinfo)".into(),
            proof: Verdict::Likely,
        }];
        if let Some(opts) = &guest.kernel_hardening {
            let on: Vec<String> = opts
                .iter()
                .filter(|(_, e)| *e)
                .map(|(n, _)| n.clone())
                .collect();
            ev.push(Evidence {
                source: "kernel-config".into(),
                detail: if on.is_empty() {
                    format!("{}/{} hardening options enabled in /proc/config.gz", 0, opts.len())
                } else {
                    format!("enabled: {}", on.join(", "))
                },
                proof: Verdict::Likely,
            });
        }
        (
            verdict,
            "SMAP/SMEP/IBPB/STIBP".to_string(),
            ev,
        )
    } else if flags_present >= 2 {
        (
            Verdict::Likely,
            format!("{flags_present}/4 CPU mitigations"),
            vec![Evidence {
                source: "sysfs".into(),
                detail: format!(
                    "partial CPU mitigations: smap={} smep={} ibpb={} stibp={}",
                    guest.smap, guest.smep, guest.ibpb, guest.stibp
                ),
                proof: Verdict::Likely,
            }],
        )
    } else {
        (
            Verdict::Unknown,
            "no CPU mitigations".to_string(),
            vec![],
        )
    };

    // 6. Hardware Backed Entropy.
    // /dev/hwrng + RDRAND/RDSEED are kernel self-reports (a malicious kernel
    // could claim them). The TPM nonce is a genuine pinned-root proof of a
    // live TPM, but that proves the TPM, not hwrng → fact stays `likely`.
    let hw_entropy = if guest.hwrng && (guest.rdrand || guest.rdseed) {
        let mut ev = vec![Evidence {
            source: "sysfs".into(),
            detail: format!(
                "/dev/hwrng present; CPU RDRAND={} RDSEED={} (kernel self-reported)",
                guest.rdrand, guest.rdseed
            ),
            proof: Verdict::Likely,
        }];
        if nitro.chain || nitro.ok {
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: "TPM2_GetRandom returned a 32-byte nonce (pinned-root proof of a live TPM, not of hwrng)".into(),
                proof: Verdict::True,
            });
        }
        (
            Verdict::Likely,
            "/dev/hwrng + RDRAND/RDSEED (self-reported)".to_string(),
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "not observed".to_string(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: format!(
                    "/dev/hwrng={} RDRAND={} RDSEED={}",
                    guest.hwrng, guest.rdrand, guest.rdseed
                ),
                proof: Verdict::Unknown,
            }],
        )
    };

    // 7. Hardware Backed Ring Isolation (SVSM).
    let ring_iso = if snp.report {
        let at_vmpl = snp.vmpl.as_deref() != Some("0");
        let verdict = if at_vmpl { snp_proof } else { Verdict::Unknown };
        let mut ev = vec![Evidence {
            source: "sev-snp".into(),
            detail: format!(
                "CPU-enforced VMPL privilege rings; guest runs at VMPL={}",
                snp.vmpl.as_deref().unwrap_or("?")
            ),
            proof: verdict,
        }];
        if at_vmpl {
            ev.extend(amd_anchor_ev(snp));
        }
        (
            verdict,
            format!("SEV-SNP VMPL rings ({snp_tag})"),
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "no SEV-SNP report".to_string(),
            vec![],
        )
    };

    // 8. Hardware Network Isolation.
    let nitro_ena = guest.nic_vendor.as_deref() == Some("0x1d0f");
    let net_iso = if nitro_ena {
        let mut ev = vec![Evidence {
            source: "sysfs".into(),
            detail: format!(
                "Nitro ENA vNIC (driver={}, vendor 0x1d0f Amazon); per-VM virtual NIC",
                guest.nic_driver.as_deref().unwrap_or("?")
            ),
            proof: Verdict::Likely,
        }];
        if let Some(it) = &imds.instance_type {
            ev.push(Evidence {
                source: "imds".into(),
                detail: format!("EC2 instance-type {it} (Nitro platform)"),
                proof: Verdict::Likely,
            });
        }
        ev.push(Evidence {
            source: "note".into(),
            detail: "per-VM vNIC isolation is architectural; not cryptographically provable from the guest"
                .into(),
            proof: Verdict::Likely,
        });
        (
            Verdict::Likely,
            "Nitro ENA per-VM vNIC".to_string(),
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "vNIC not identified".to_string(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: format!(
                    "eth0 driver={} vendor={}",
                    guest.nic_driver.as_deref().unwrap_or("?"),
                    guest.nic_vendor.as_deref().unwrap_or("?")
                ),
                proof: Verdict::Unknown,
            }],
        )
    };

    Branch {
        name: "Security".into(),
        facts: vec![
            Fact {
                name: "Memory Encryption".into(),
                value: mem_enc.1,
                verdict: mem_enc.0,
                evidence: mem_enc.2,
            },
            Fact {
                name: "Filesystem Encryption".into(),
                value: fs_enc.1,
                verdict: fs_enc.0,
                evidence: fs_enc.2,
            },
            Fact {
                name: "Memory Isolation".into(),
                value: mem_iso.1,
                verdict: mem_iso.0,
                evidence: mem_iso.2,
            },
            Fact {
                name: "Secure Boot".into(),
                value: sb_value,
                verdict: sb_verdict,
                evidence: sb_ev,
            },
            Fact {
                name: "Hardened Kernel".into(),
                value: hk_value,
                verdict: hk_verdict,
                evidence: hk_ev,
            },
            Fact {
                name: "Hardware Backed Entropy".into(),
                value: hw_entropy.1,
                verdict: hw_entropy.0,
                evidence: hw_entropy.2,
            },
            Fact {
                name: "Hardware Backed Ring Isolation (SVSM)".into(),
                value: ring_iso.1,
                verdict: ring_iso.0,
                evidence: ring_iso.2,
            },
            Fact {
                name: "Hardware Network Isolation".into(),
                value: net_iso.1,
                verdict: net_iso.0,
                evidence: net_iso.2,
            },
        ],
    }
}

fn hardware_branch(
    nitro: &NitroFacts,
    snp: &SnpFacts,
    guest: &GuestFacts,
) -> Branch {
    // CPU.
    // /proc/cpuinfo is kernel self-report; the report's CPUID anchors to
    // AMD's root when amd_anchored(), otherwise only to the platform VLEK.
    let snp_cpu_proof = if snp.amd_anchored() { Verdict::True } else { Verdict::Likely };
    let (cpu_verdict, cpu_value, cpu_ev) = if snp.report {
        let mut ev = vec![Evidence {
            source: "sev-snp".into(),
            detail: format!(
                "CPUID Family {} / Model {} / Stepping {} (signed SEV-SNP report{})",
                snp.cpuid_family.as_deref().unwrap_or("?"),
                snp.cpuid_model.as_deref().unwrap_or("?"),
                snp.cpuid_stepping.as_deref().unwrap_or("?"),
                if snp.amd_anchored() {
                    ", anchored to the AMD root".to_string()
                } else {
                    ", VLEK-anchored only".to_string()
                },
            ),
            proof: snp_cpu_proof,
        }];
        if let Some(m) = &guest.cpu_model {
            ev.push(Evidence {
                source: "sysfs".into(),
                detail: format!("/proc/cpuinfo: {m} (kernel self-reported)"),
                proof: Verdict::Likely,
            });
        }
        (
            snp_cpu_proof,
            guest.cpu_model.clone().unwrap_or_else(|| "AMD EPYC (Milan)".into()),
            ev,
        )
    } else if let Some(m) = &guest.cpu_model {
        (
            Verdict::Likely,
            m.clone(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: format!("/proc/cpuinfo: {m}"),
                proof: Verdict::Likely,
            }],
        )
    } else {
        (
            Verdict::Unknown,
            "unknown".to_string(),
            vec![],
        )
    };

    // TPM.
    // The one fact that stays `true`: the attestation doc is signed by AWS,
    // the chain verifies to the EMBEDDED (pinned) AWS Nitro Enclaves root CA,
    // and a TPM2_GetRandom nonce echo proves freshness. A malicious guest or
    // platform cannot forge this without breaking the signature or the pin.
    let (tpm_verdict, tpm_value, tpm_ev) = if nitro.ok {
        let mut ev = vec![Evidence {
            source: "nitro-tpm".into(),
            detail: "attestation verified: ES384 signature + chain to the pinned AWS Nitro Enclaves root + nonce echo (freshness)".into(),
            proof: Verdict::True,
        }];
        if !nitro.chain_cns.is_empty() {
            let mut chain = nitro.chain_cns.join(" \u{2192} ");
            if let Some(rcn) = &nitro.root_cn {
                chain.push_str(&format!(" \u{2192} {rcn} (pinned root)"));
            }
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!("endorsement chain: {chain}"),
                proof: Verdict::True,
            });
        }
        if let Some(fp) = &nitro.root_fp {
            let root_name = nitro
                .root_cn
                .clone()
                .unwrap_or_else(|| "AWS Nitro Enclaves root".into());
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!("root of trust: {root_name}, SHA-256 {fp} (embedded/pinned in this binary; the chain above verified against it)"),
                proof: Verdict::True,
            });
        }
        if let Some(mid) = &nitro.module_id {
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!("module {mid}"),
                proof: Verdict::True,
            });
        }
        if let Some(ud) = &nitro.user_data {
            let display = if ud.iter().all(|b| b.is_ascii() && (b.is_ascii_graphic() || *b == b' ')) {
                String::from_utf8_lossy(ud).into_owned()
            } else {
                ud.iter().map(|b| format!("{b:02x}")).collect()
            };
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!("user_data (echoed by the signer into the signed document; ES384-covered, chain-verified to the pinned AWS root): {display}"),
                proof: Verdict::True,
            });
        }
        (
            Verdict::True,
            "NitroTPM".to_string(),
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "not verified".to_string(),
            vec![Evidence {
                source: "nitro-tpm".into(),
                detail: nitro.error.clone().unwrap_or_else(|| "no attestation".into()),
                proof: Verdict::Unknown,
            }],
        )
    };

    // Memory.
    let (mem_value, mem_ev) = match guest.mem_total_kb {
        Some(kb) => (
            format!("~{} GB", (kb as f64 / 1024.0 / 1024.0).round() as u64),
            vec![Evidence {
                source: "sysfs".into(),
                detail: format!("MemTotal {kb} kB"),
                proof: Verdict::Likely,
            }],
        ),
        None => (
            "unknown".to_string(),
            vec![],
        ),
    };

    // Storage.
    let disks = crate::facts::Facts::collect(None).disks;
    let real = real_storage_lines(&disks);
    let (sto_value, sto_ev) = if real.is_empty() {
        ("unknown".to_string(), vec![])
    } else {
        let names: Vec<&str> = real
            .iter()
            .map(|l| l.split_whitespace().next_back().unwrap_or(""))
            .collect();
        (
            names.join(", "),
            real
                .iter()
                .map(|d| Evidence {
                    source: "sysfs".into(),
                    detail: d.clone(),
                    proof: Verdict::Likely,
                })
                .collect(),
        )
    };

    Branch {
        name: "Hardware".into(),
        facts: vec![
            Fact {
                name: "CPU".into(),
                value: cpu_value,
                verdict: cpu_verdict,
                evidence: cpu_ev,
            },
            Fact {
                name: "TPM".into(),
                value: tpm_value,
                verdict: tpm_verdict,
                evidence: tpm_ev,
            },
            Fact {
                name: "Memory".into(),
                value: mem_value,
                verdict: Verdict::Likely,
                evidence: mem_ev,
            },
            Fact {
                name: "Storage".into(),
                value: sto_value,
                verdict: Verdict::Likely,
                evidence: sto_ev,
            },
        ],
    }
}

fn software_branch(nitro: &NitroFacts, snp: &SnpFacts, guest: &GuestFacts) -> Branch {
    // OS.
    let (os_verdict, os_value, os_ev) = if let Some(os) = &guest.os {
        (
            Verdict::Likely,
            os.clone(),
            vec![Evidence {
                source: "sysfs".into(),
                detail: "self-reported via /etc/os-release (not independently proven)".into(),
                proof: Verdict::Likely,
            }],
        )
    } else {
        (
            Verdict::Unknown,
            "unknown".to_string(),
            vec![],
        )
    };

    // Kernel.
    let (k_verdict, k_value, k_ev) = if let Some(k) = &guest.kernel {
        let mut ev = vec![Evidence {
            source: "sysfs".into(),
            detail: format!("/proc/sys/kernel/osrelease = {k}"),
            proof: Verdict::Likely,
        }];
        if nitro.ok {
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: "kernel is measured into the boot PCRs (measured boot); PCR state in the signed document"
                    .into(),
                proof: Verdict::Likely,
            });
        }
        (
            Verdict::Likely,
            k.clone(),
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "unknown".to_string(),
            vec![],
        )
    };

    // Measured boot: the boot artifacts are measured into TWO independent
    // vendor roots — the PCRs in the AWS-signed NitroTPM document and the
    // launch measurement in the AMD-signed SEV-SNP report.
    let (mb_verdict, mb_value, mb_ev) = if nitro.ok && nitro.pcr_count > 0 {
        let mut ev = vec![Evidence {
            source: "nitro-tpm".into(),
            detail: format!(
                "{} PCR values carried in the signed attestation document",
                nitro.pcr_count
            ),
            proof: Verdict::True,
        }];
        let amd_part = snp.amd_anchored() && snp.measurement.is_some();
        if let (true, Some(m)) = (amd_part, &snp.measurement) {
            ev.push(Evidence {
                source: "sev-snp".into(),
                detail: format!(
                    "SEV-SNP launch measurement (boot image hash, AMD-PSP attested): {m}\u{2026}"
                ),
                proof: Verdict::True,
            });
        }
        (
            Verdict::True,
            if amd_part {
                format!("{} PCRs in signed doc + SNP launch measurement", nitro.pcr_count)
            } else {
                format!("{} PCRs in signed doc", nitro.pcr_count)
            },
            ev,
        )
    } else {
        (
            Verdict::Unknown,
            "no PCR evidence".to_string(),
            vec![],
        )
    };

    // Root integrity: the boot state is pinned (expected PCRs) and attested.
    // "The root filesystem cannot be altered between boots without
    // detection" requires pinned expected values — the attested PCR state
    // only proves what the pinned policy says is the expected state.
    let (ri_verdict, ri_value, ri_ev) = if nitro.ok && nitro.policy_len > 0 {
        let origin = match &nitro.policy_source {
            Some(src) => format!(
                "{} expected PCRs DERIVED FROM SOURCE {src} (rebuilt and measured locally by the verifier) match the AWS-signed attested document: the boot state is exactly this source",
                nitro.policy_len
            ),
            None => format!(
                "{} pinned PCR values match the AWS-signed attested document: the boot state (firmware, boot manager, kernel, measured root) is the pinned state",
                nitro.policy_len
            ),
        };
        let mut ev = vec![Evidence {
            source: "nitro-tpm".into(),
            detail: origin,
            proof: Verdict::True,
        }];
        if snp.amd_anchored() {
            ev.push(Evidence {
                source: "sev-snp".into(),
                detail: "SEV-SNP launch measurement (kernel/cmdline/initrd) attested by the AMD PSP — independent of the AWS PCR pin"
                    .into(),
                proof: Verdict::True,
            });
        }
        (
            Verdict::True,
            format!("{} PCRs pinned + matched (signed doc)", nitro.policy_len),
            ev,
        )
    } else {
        let mut ev = Vec::new();
        if nitro.ok && nitro.pcr_count > 0 {
            ev.push(Evidence {
                source: "nitro-tpm".into(),
                detail: format!(
                    "{} PCRs in the signed doc but NO pinned expected values: drift between boots is not detected",
                    nitro.pcr_count
                ),
                proof: Verdict::Likely,
            });
        }
        ev.push(Evidence {
            source: "note".into(),
            detail: "pin a known-good baseline (bootproof verify-nitro --emit-pcrs) as the --pcr-policy; UKI/rootfs image-hash (PCR17) measurement is a later phase; dm-verity not observed on the root"
                .into(),
            proof: Verdict::Unknown,
        });
        (Verdict::Unknown, "no pinned PCR policy".to_string(), ev)
    };

    Branch {
        name: "Software".into(),
        facts: vec![
            Fact {
                name: "OS".into(),
                value: os_value,
                verdict: os_verdict,
                evidence: os_ev,
            },
            Fact {
                name: "Kernel".into(),
                value: k_value,
                verdict: k_verdict,
                evidence: k_ev,
            },
            Fact {
                name: "Measured Boot".into(),
                value: mb_value,
                verdict: mb_verdict,
                evidence: mb_ev,
            },
            Fact {
                name: "Root Integrity (measured)".into(),
                value: ri_value,
                verdict: ri_verdict,
                evidence: ri_ev,
            },
        ],
    }
}

fn bool_str(b: Option<bool>) -> String {
    match b {
        Some(true) => "on".into(),
        Some(false) => "off".into(),
        None => "?".into(),
    }
}

fn bool_opt(b: Option<bool>) -> String {
    match b {
        Some(true) => "true".into(),
        Some(false) => "false".into(),
        None => "?".into(),
    }
}

/// A short note describing what the common measured-boot PCRs lock a
/// TPM-bound key to (so "locked to PCRs" is meaningful to a reader).
fn pcr_binding_note() -> String {
    "PCR0=UEFI firmware, PCR2=Secure-Boot DB, PCR4=kernel image, PCR11=kernel cmdline"
        .to_string()
}

/// Filter the disk lines down to the real storage devices (drop ram*/loop*).
fn real_storage_lines(disks: &[String]) -> Vec<String> {
    disks
        .iter()
        .filter(|l| {
            let name = l.split_whitespace().next_back().unwrap_or("");
            !name.starts_with("ram") && !name.starts_with("loop")
        })
        .cloned()
        .collect()
}

// ── render ────────────────────────────────────────────────────────────────────

/// Display width in terminal columns. All non-ASCII used here (—, →, ←, ◆)
/// are single-width, so char count is exact.
fn disp_width(s: &str) -> usize {
    s.chars().count()
}

/// Wrap `text` so every emitted line is at most `width` display columns.
/// Every line begins with `prefix` (so continuations align under the
/// detail text). Words longer than the remaining space are hard-broken.
fn wrap_line(prefix: &str, text: &str, width: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let avail = width.saturating_sub(disp_width(prefix));
    for word in text.split_whitespace() {
        if disp_width(word) > avail {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            let mut chunk = String::new();
            for c in word.chars() {
                if disp_width(&chunk) == avail {
                    out.push(format!("{}{}", prefix, chunk));
                    chunk.clear();
                }
                chunk.push(c);
            }
            cur = format!("{}{}", prefix, chunk);
            continue;
        }
        let trial = if cur.is_empty() {
            format!("{}{}", prefix, word)
        } else {
            format!("{} {}", cur, word)
        };
        if disp_width(&trial) <= width {
            cur = trial;
        } else {
            out.push(std::mem::take(&mut cur));
            cur = format!("{}{}", prefix, word);
        }
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

/// Render the tree as an indented, human-friendly text block, wrapped to
/// 80 columns.
pub fn render(tree: &TrustTree) -> String {
    const WIDTH: usize = 80;
    let mut out = String::new();
    out.push_str("TRUST TREE\n");
    for branch in &tree.branches {
        out.push_str(&format!("◆ {}\n", branch.name));
        for fact in &branch.facts {
            let fact_text = if fact.value.is_empty() {
                format!("{}: {}", fact.name, fact.verdict)
            } else {
                format!("{}: {} — {}", fact.name, fact.verdict, fact.value)
            };
            if disp_width(&fact_text) + 2 <= WIDTH {
                out.push_str("  ");
                out.push_str(&fact_text);
                out.push('\n');
            } else {
                for line in wrap_line("  ", &fact_text, WIDTH) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            for ev in &fact.evidence {
                let prefix = format!("    [{}] ", ev.source);
                if disp_width(&prefix) + disp_width(&ev.detail) <= WIDTH {
                    out.push_str(&prefix);
                    out.push_str(&ev.detail);
                    out.push('\n');
                } else {
                    for line in wrap_line(&prefix, &ev.detail, WIDTH) {
                        out.push_str(&line);
                        out.push('\n');
                    }
                }
            }
        }
    }
    out
}

/// Serialize the tree to pretty JSON.
pub fn to_json(tree: &TrustTree) -> String {
    serde_json::to_string_pretty(tree).unwrap_or_default()
}

// ── succinct summary (default output) ─────────────────────────────────────────

/// The vendors acting as the cryptographic ROOT OF TRUST for an evidence
/// source. Only evidence that is `True`-strength counts for a fact's vendor
/// list, so self-reported (likely) lines never contribute a vendor.
fn vendor_of(source: &str) -> Option<&'static str> {
    match source {
        "nitro-tpm" => Some("AWS"),
        "sev-snp" => Some("AMD"),
        "imds" => Some("AWS"), // only signed-IIDD lines reach True proof
        _ => None,
    }
}

fn fact_vendors(fact: &Fact) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    for e in &fact.evidence {
        if e.proof == Verdict::True {
            if let Some(w) = vendor_of(&e.source) {
                if !v.contains(&w) {
                    v.push(w);
                }
            }
        }
    }
    v
}

/// The facts shown in the default (succinct) output, in order.
fn summary_rows(tree: &TrustTree) -> Vec<(&'static str, &Fact)> {
    let find = |b: &str, f: &str| -> Option<&Fact> {
        tree.branches
            .iter()
            .find(|x| x.name == b)
            .and_then(|br| br.facts.iter().find(|x| x.name == f))
    };
    let mut rows: Vec<(&'static str, &Fact)> = Vec::new();
    for (label, branch, name) in [
        ("level", "Cryptography", "Attestation Level"),
        ("instance", "Custody", "Instance"),
        ("account", "Custody", "Owner / Account"),
        ("region", "Custody", "Location"),
        ("cpu", "Hardware", "CPU"),
        ("memory", "Security", "Memory Encryption"),
        ("isolation", "Security", "Memory Isolation"),
        ("tpm", "Hardware", "TPM"),
        ("boot", "Software", "Measured Boot"),
        ("rootfs", "Software", "Root Integrity (measured)"),
        ("os", "Software", "OS"),
        ("secure boot", "Security", "Secure Boot"),
        ("provenance", "Provenance", "Source / Provenance"),
    ] {
        if let Some(f) = find(branch, name) {
            rows.push((label, f));
        }
    }
    rows
}

fn verdict_mark(v: Verdict) -> &'static str {
    match v {
        Verdict::True => "✓",
        Verdict::Likely => "~",
        Verdict::False => "✗",
        Verdict::Unknown => "?",
    }
}

/// Shorten a fact value for the succinct view: drop the root-anchoring
/// suffix (the vendor column already says that) and the redundant vendor
/// prefix on account/region lines.
fn concise_value(label: &str, value: &str) -> String {
    let v = value
        .replace(" (AMD-root-anchored)", "")
        .replace(" (platform-anchored)", "");
    match label {
        "account" => v.strip_prefix("AWS account ").unwrap_or(&v).to_string(),
        "region" => v.strip_prefix("AWS ").unwrap_or(&v).to_string(),
        _ => v,
    }
}

/// Render the default succinct output: the most important facts, each with
/// the vendor root(s) whose cryptographic attestation proves it.
pub fn render_summary(tree: &TrustTree) -> String {
    let rows = summary_rows(tree);
    let label_w = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0)
        .max(4);
    let value_w = 40usize;
    let mut out = String::from("TRUST SUMMARY\n");
    for (label, fact) in &rows {
        let vendors = fact_vendors(fact);
        let vendor_str = if vendors.is_empty() {
            "(self)".to_string()
        } else {
            vendors.join(" ")
        };
        let display = concise_value(label, &fact.value);
        let mut lines = wrap_line("", &display, value_w);
        let first = lines.remove(0);
        out.push_str(&format!(
            " {m} {label:<lw$}  {first:<vw$}  {v}\n",
            m = verdict_mark(fact.verdict),
            label = label,
            lw = label_w,
            first = first,
            vw = value_w,
            v = vendor_str,
        ));
        let cont = " ".repeat(3 + label_w + 2);
        for line in lines {
            out.push_str(&format!("{cont}{line}\n"));
        }
    }
    if let Some(binding) = tree
        .branches
        .iter()
        .find(|x| x.name == "Cryptography")
        .and_then(|br| br.facts.iter().find(|x| x.name == "Cross-Attestation Binding"))
    {
        if binding.verdict == Verdict::True {
            out.push('\n');
            let text = "binding: a fresh 32-byte nonce is embedded in BOTH the AWS-signed NitroTPM \
document and the AMD-signed SEV-SNP report — neither can be replayed or \
spliced from another machine or run.";
            for (i, line) in wrap_line("", text, 78).into_iter().enumerate() {
                out.push_str(&format!("  {}{}\n", if i == 0 { "" } else { "" }, line));
            }
        }
    }
    out.push_str("\n  (--expert: full evidence tree; --json: machine output)\n");
    out
}

#[derive(Serialize)]
struct SummaryFact {
    name: &'static str,
    verdict: Verdict,
    value: String,
    vendors: Vec<&'static str>,
}

#[derive(Serialize)]
struct Summary {
    facts: Vec<SummaryFact>,
    binding: Option<SummaryFact>,
}

/// Machine-readable version of the default succinct output.
pub fn to_summary_json(tree: &TrustTree) -> String {
    let mut facts: Vec<SummaryFact> = Vec::new();
    for (label, f) in summary_rows(tree) {
        facts.push(SummaryFact {
            name: label,
            verdict: f.verdict,
            value: f.value.clone(),
            vendors: fact_vendors(f),
        });
    }
    let binding = tree
        .branches
        .iter()
        .find(|x| x.name == "Cryptography")
        .and_then(|br| br.facts.iter().find(|x| x.name == "Cross-Attestation Binding"))
        .filter(|f| f.verdict == Verdict::True)
        .map(|f| SummaryFact {
            name: "binding",
            verdict: f.verdict,
            value: f.value.clone(),
            vendors: fact_vendors(f),
        });
    serde_json::to_string_pretty(&Summary { facts, binding }).unwrap_or_default()
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Options for the local trust tree (`bootproof verify` with no target).
pub struct Opts {
    /// TPM kernel character device (default /dev/tpm0).
    pub device: PathBuf,
    /// Connect via tpm-bridge TCP endpoint (host:port). Overrides --device.
    pub tcp: Option<String>,
    /// Raw NV index of the persistent NSM scratch buffer (hex u32).
    pub nv_index: u32,
    /// Emit JSON instead of the rendered output.
    pub json: bool,
    /// Full evidence tree with all vendor detail (default: succinct summary).
    pub expert: bool,
    /// Pinned expected-PCR policy file (JSON `{{"<idx>": "<hex|b64>"}}`).
    /// When set, the attested PCRs must match; the Root Integrity fact and
    /// Measured Boot reflect the pin.
    pub pcr_policy: Option<PathBuf>,
    /// Caller metadata placed in the NSM attestation request. The signer
    /// echoes it into the AWS-signed document, so it becomes metadata
    /// authenticated by the pinned AWS root and bound to the same signed
    /// PCRs/nonce as the rest of the attestation.
    pub user_data: Option<String>,
    /// Require at least this attestation level (0..=3). Exit 4 if the
    /// derived level is below it.
    pub min_level: Option<u8>,
}

/// Gather all evidence, build the tree, and print it.
pub fn run(opts: Opts) -> anyhow::Result<i32> {
    let snp = collect_snp();
    let binding_nonce = snp.report_data.as_ref().map(|rd| rd[..32].to_vec());
    let policy = match &opts.pcr_policy {
        Some(p) => load_pcr_policy_file(p)?,
        None => PcrPolicy::default(),
    };
    let user_data = opts.user_data.as_ref().map(|s| s.as_bytes().to_vec());
    let nitro = collect_nitro(&opts.device, &opts.tcp, opts.nv_index, binding_nonce, &policy, user_data);
    let level = TrustLevel::derive(&nitro, &snp, nitro.device);
    let imds = collect_imds();
    let iidd = collect_iidd(nitro.region.as_deref());
    let guest = collect_guest();
    let prov = collect_provenance();
    let tree = build_tree_with(nitro, snp, imds, iidd, guest, &prov);
    if opts.json {
        println!(
            "{}",
            if opts.expert {
                to_json(&tree)
            } else {
                to_summary_json(&tree)
            }
        );
    } else if opts.expert {
        print!("{}", render(&tree));
    } else {
        print!("{}", render_summary(&tree));
    }
    if let Some(min) = opts.min_level {
        match TrustLevel::from_u8(min) {
            Some(minl) if level >= minl => {}
            Some(minl) => {
                eprintln!(
                    "attestation level {} ({}) below required {} ({})",
                    level.label(),
                    level.description(),
                    minl.label(),
                    minl.description()
                );
                return Ok(4);
            }
            None => return Err(anyhow::anyhow!("--min-level must be 0, 1, 2, or 3")),
        }
    }
    Ok(0)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::True.to_string(), "true");
        assert_eq!(Verdict::Likely.to_string(), "likely");
        assert_eq!(Verdict::False.to_string(), "false");
        assert_eq!(Verdict::Unknown.to_string(), "unknown");
    }

    #[test]
    fn trust_level_derive() {
        // No device at all.
        assert_eq!(
            TrustLevel::derive(&NitroFacts::default(), &SnpFacts::default(), false),
            TrustLevel::None
        );
        // Device responds but nothing verifies to a pinned root: L0.
        let mut f = NitroFacts::default();
        f.device = true;
        f.error = Some("attestation_document: vendor command unsupported".into());
        assert_eq!(
            TrustLevel::derive(&f, &SnpFacts::default(), f.device),
            TrustLevel::L0
        );
        // Hardware TPM chain verified, no CVM report: L1.
        let mut n = NitroFacts::default();
        n.device = true;
        n.ok = true;
        n.chain = true;
        assert_eq!(
            TrustLevel::derive(&n, &SnpFacts::default(), n.device),
            TrustLevel::L1
        );
        // CVM report anchored but stale (no fresh report_data): still L1.
        let mut s = SnpFacts::default();
        s.report = true;
        s.vlek_verified = Some(true);
        s.amd_chain_ok = Some(true);
        assert_eq!(TrustLevel::derive(&n, &s, n.device), TrustLevel::L1);
        // Fresh, anchored report with the shared nonce: L2.
        s.report_data = Some(vec![0u8; 32]);
        assert_eq!(TrustLevel::derive(&n, &s, n.device), TrustLevel::L2);
        // Anchored CVM without a verified TPM is NOT L2 under the model.
        let mut n2 = NitroFacts::default();
        n2.device = true;
        assert_eq!(TrustLevel::derive(&n2, &s, n2.device), TrustLevel::L0);
    }

    #[test]
    fn trust_level_from_u8() {
        assert_eq!(TrustLevel::from_u8(0), Some(TrustLevel::L0));
        assert_eq!(TrustLevel::from_u8(1), Some(TrustLevel::L1));
        assert_eq!(TrustLevel::from_u8(2), Some(TrustLevel::L2));
        assert_eq!(TrustLevel::from_u8(3), Some(TrustLevel::L3));
        assert_eq!(TrustLevel::from_u8(4), None);
        assert!(TrustLevel::None < TrustLevel::L0);
        assert!(TrustLevel::L0 < TrustLevel::L1);
        assert!(TrustLevel::L1 < TrustLevel::L2);
        assert!(TrustLevel::L2 < TrustLevel::L3);
    }

    #[test]
    fn region_token_detection() {
        assert!(is_region_token("us-east-2"));
        assert!(is_region_token("eu-west-3"));
        assert!(is_region_token("ap-south-1"));
        assert!(!is_region_token("aws"));
        assert!(!is_region_token("nitro-enclaves"));
        assert!(!is_region_token("i-02a44cb68978c43af"));
        assert!(!is_region_token("us-east"));
    }

    #[test]
    fn region_from_cn_parses() {
        assert_eq!(
            region_from_cn("i-02a44cb68978c43af-tpm0000000000000000.us-east-2.aws"),
            Some("us-east-2".to_string())
        );
        assert_eq!(
            region_from_cn("86042cabc.us-east-2.aws.nitro-enclaves"),
            Some("us-east-2".to_string())
        );
        assert_eq!(region_from_cn("aws.nitro-enclaves"), None);
    }

    const SNP_DISPLAY: &str = "\
Attestation Report:

Version:                      5

Guest Policy (0x2030000):
  ABI Major:     0
  SMT Allowed:   true
  Debug Allowed: false
  Page Swap Disable: true

VMPL:                         1

Platform Info (39):
  TSME Enabled:              true
  ECC Enabled:               true

Key Information:
    signing key:        vlek

Measurement:
50 7E 82 D2 7E A5 B9 51 DD 76 5A 3E B3 1B A5 F5
82 67 3B 30 1D 69 83 DE D4 82 D3 FE B0 66 CB 68

CPUID Family ID:              25
CPUID Model ID:               1
CPUID Stepping:               1

Current Version:              1.58.1
";

    #[test]
    fn snpguest_field_parsing() {
        assert_eq!(field_value(SNP_DISPLAY, "CPUID Family ID"), Some("25".into()));
        assert_eq!(field_value(SNP_DISPLAY, "VMPL"), Some("1".into()));
        assert_eq!(field_value(SNP_DISPLAY, "signing key"), Some("vlek".into()));
        assert_eq!(field_value(SNP_DISPLAY, "Current Version"), Some("1.58.1".into()));
        assert_eq!(policy_hex(SNP_DISPLAY), Some("2030000".into()));
        assert_eq!(field_bool(SNP_DISPLAY, "TSME Enabled"), Some(true));
        assert_eq!(field_bool(SNP_DISPLAY, "Debug Allowed"), Some(false));
        assert_eq!(field_bool(SNP_DISPLAY, "Page Swap Disable"), Some(true));
        assert_eq!(
            hex_block(SNP_DISPLAY, "Measurement"),
            Some("507e82d27ea5b951dd765a3eb31ba5f582673b301d6983ded482d3feb066cb68".into())
        );
    }

    #[test]
    fn render_has_branches_in_order() {
        let tree = build_tree(
            NitroFacts::default(),
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let names: Vec<&str> = tree.branches.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Cryptography",
                "Custody",
                "Security",
                "Access",
                "Hardware",
                "Software"
            ]
        );
        let s = render(&tree);
        for b in [
            "◆ Cryptography",
            "◆ Custody",
            "◆ Security",
            "◆ Access",
            "◆ Hardware",
            "◆ Software",
        ] {
            assert!(s.contains(b), "missing {b}");
        }
        // Cryptography entries are N/A placeholders.
        assert!(s.contains("Ephemeral Key: unknown"));
        assert!(s.contains("Provider Key: unknown"));
        // The 8 security facts are present.
        for name in [
            "Memory Encryption",
            "Filesystem Encryption",
            "Memory Isolation",
            "Secure Boot",
            "Hardened Kernel",
            "Hardware Backed Entropy",
            "Hardware Backed Ring Isolation (SVSM)",
            "Hardware Network Isolation",
        ] {
            assert!(s.contains(name), "missing {name}");
        }
        // Custody + Access facts are present.
        for name in [
            "Owner / Account",
            "Instance",
            "Location",
            "Custody Chain",
            "Administrative Access",
        ] {
            assert!(s.contains(name), "missing {name}");
        }
    }

    #[test]
    fn render_is_valid_json_roundtrip() {
        let tree = build_tree(
            NitroFacts::default(),
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let j = to_json(&tree);
        let parsed: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed["branches"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn render_wraps_to_80_columns() {
        let long = "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd";
        let tree = TrustTree {
            branches: vec![Branch {
                name: "Security".into(),
                facts: vec![Fact {
                    name: "A Very Long Fact Name That Exceeds The Width".into(),
                    value: format!("value with {long} and more words to force wrapping to happen here"),
                    verdict: Verdict::True,
                    evidence: vec![Evidence {
                        source: "nitro-tpm".into(),
                        detail: format!(
                            "root of trust: aws.nitro-enclaves, SHA-256 {long} (embedded/pinned in this binary; the chain above verified against it)"
                        ),
                        proof: Verdict::True,
                    }],
                }],
            }],
        };
        for line in render(&tree).lines() {
            assert!(
                disp_width(line) <= 80,
                "line {} cols: {:?}",
                disp_width(line),
                line
            );
        }
    }

    #[test]
    fn wrap_line_respects_width_and_hard_breaks() {
        // A 64-char compact fingerprint fits on its own line intact.
        let long = "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd";
        let lines = wrap_line("    [x] ", &format!("sha {long} tail"), 80);
        for l in &lines {
            assert!(disp_width(l) <= 80, "{l}");
        }
        assert!(lines.iter().any(|l| l.contains(long)));
        // A word longer than the line is hard-broken, never exceeding width.
        let huge = "a".repeat(200);
        let lines = wrap_line("    [x] ", &format!("pre {huge} post"), 80);
        for l in &lines {
            assert!(disp_width(l) <= 80, "{l}");
        }
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn verdicts_degrade_to_unknown_without_evidence() {
        let tree = build_tree(
            NitroFacts::default(),
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let sec = &tree.branches[2];
        assert_eq!(sec.facts[0].verdict, Verdict::Unknown); // Memory Encryption
        assert_eq!(sec.facts[1].verdict, Verdict::Unknown); // Filesystem Encryption
        assert_eq!(sec.facts[3].verdict, Verdict::Unknown); // Secure Boot (UEFI active, sb absent => None)
        assert_eq!(tree.branches[3].facts[0].verdict, Verdict::Unknown); // Administrative Access
    }

    #[test]
    fn cross_attestation_binding() {
        // Bound: fresh report with report_data + verified NitroTPM attestation.
        let mut snp = SnpFacts::default();
        snp.report = true;
        snp.report_data = Some(vec![0u8; 64]);
        let mut nitro = NitroFacts::default();
        nitro.ok = true;
        let tree = build_tree(
            nitro, snp, ImdsFacts::default(), IiddFacts::default(), GuestFacts::default()
        );
        let crypto = &tree.branches[0];
        let fact = crypto
            .facts
            .iter()
            .find(|f| f.name == "Cross-Attestation Binding")
            .expect("binding fact present");
        assert_eq!(fact.verdict, Verdict::True);

        // Unbound: no evidence at all.
        let tree = build_tree(
            NitroFacts::default(),
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let fact = tree
            .branches[0]
            .facts
            .iter()
            .find(|f| f.name == "Cross-Attestation Binding")
            .expect("binding fact present");
        assert_eq!(fact.verdict, Verdict::Unknown);
    }
    // Captured on i-02a44cb68978c43af (us-east-2) 2026-08-27: the full
    // PKCS#7 (base64) of the instance identity document. Verifies against
    // the pinned us-east-2 DSA cert in data/iidd/.
    const IIDD_FIXTURE_PKCS7_B64: &str = concat!(
        "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEgg",
        "HdewogICJhY2NvdW50SWQiIDogIjQxMjU0MTAzMzQ3MiIsCiAgImFyY2hpdGVjdHVyZSIg",
        "OiAieDg2XzY0IiwKICAiYXZhaWxhYmlsaXR5Wm9uZSIgOiAidXMtZWFzdC0yYyIsCiAgIm",
        "JpbGxpbmdQcm9kdWN0cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVs",
        "bCwKICAibWFya2V0cGxhY2VQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAiaW1hZ2VJZCIgOi",
        "AiYW1pLTA2YjM0MWI3NjYzODQ3NTE5IiwKICAiaW5zdGFuY2VJZCIgOiAiaS0wMmE0NGNi",
        "Njg5NzhjNDNhZiIsCiAgImluc3RhbmNlVHlwZSIgOiAiYzZhLmxhcmdlIiwKICAia2Vybm",
        "VsSWQiIDogbnVsbCwKICAicGVuZGluZ1RpbWUiIDogIjIwMjYtMDgtMjRUMDE6NDY6NDNa",
        "IiwKICAicHJpdmF0ZUlwIiA6ICIxNzIuMzEuNDcuMTYiLAogICJyYW1kaXNrSWQiIDogbn",
        "VsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTIiLAogICJ2ZXJzaW9uIiA6ICIyMDE3LTA5",
        "LTMwIgp9AAAAAAAAMYIBPzCCATsCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcGA1UECBMQV2",
        "FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1hem9uIFdl",
        "YiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoIGEMBgGCSqGSIb3DQEJAz",
        "ELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDgyNDAxNDY0NFowIwYJKoZIhvcN",
        "AQkEMRYEFJJ1kGlvqRTx3230fme3tSDeAZhJMCUGCSqGSIb3DQEJNDEYMBYwCQYFKw4DAh",
        "oFAKEJBgcqhkjOOAQDMAkGByqGSM44BAMELjAsAhQZDqy30VhQIZnXb/aNIGZZ2osCegIU",
        "XdGGETyltdjASmO/fmVRJTS+sd4AAAAAAAA=",
    );


    #[test]
    fn iidd_dsa_verifies_against_pinned_cert() {
        use base64::Engine as _;
        let data = base64::engine::general_purpose::STANDARD
            .decode(IIDD_FIXTURE_PKCS7_B64)
            .unwrap();
        let (content, digest, canon, sig) = extract_pkcs7_parts(&data).expect("pkcs7 parses");
        let json: serde_json::Value = serde_json::from_slice(&content).unwrap();
        assert_eq!(json["accountId"], "412541033472");
        assert_eq!(json["instanceType"], "c6a.large");
        assert_eq!(json["region"], "us-east-2");
        let pem = IIDD_DSA_CERTS
            .iter()
            .find(|(r, _)| *r == "us-east-2")
            .map(|(_, p)| *p)
            .expect("us-east-2 cert pinned");
        let (p, q, g, y) = dsa_params(pem).expect("dsa params parse");
        let actual: [u8; 20] = sha1::Sha1::digest(&content).into();
        assert_eq!(actual, digest, "messageDigest binds the content");
        assert!(dsa_verify(&p, &q, &g, &y, &canon, &sig), "signature must verify");
        // Tampered signed attributes must NOT verify.
        let mut bad = canon.clone();
        bad[5] ^= 0x01;
        assert!(
            !dsa_verify(&p, &q, &g, &y, &bad, &sig),
            "tampered attributes must fail"
        );
        // A different region's cert must NOT verify (different key).
        let (p2, q2, g2, y2) = dsa_params(
            IIDD_DSA_CERTS
                .iter()
                .find(|(r, _)| *r == "af-south-1")
                .map(|(_, p)| *p)
                .expect("af-south-1 cert pinned"),
        )
        .expect("dsa params parse");
        assert!(
            !dsa_verify(&p2, &q2, &g2, &y2, &canon, &sig),
            "wrong-region key must fail"
        );
    }

    #[test]
    fn summary_lists_vendor_roots() {
        let mut nitro = NitroFacts::default();
        nitro.ok = true;
        nitro.chain = true;
        nitro.module_id = Some("i-02a44cb68978c43af-tpm0000000000000000".into());
        nitro.region = Some("us-east-2".into());
        nitro.pcr_count = 24;
        let mut snp = SnpFacts::default();
        snp.report = true;
        snp.vlek_verified = Some(true);
        snp.amd_chain_ok = Some(true);
        snp.measurement = Some("a1b2c3d4e5f60718".into());
        snp.report_data = Some(vec![7u8; 64]);
        let mut iidd = IiddFacts::default();
        iidd.verified = true;
        iidd.account = Some("412541033472".into());
        iidd.instance_type = Some("c6a.large".into());
        iidd.region = Some("us-east-2".into());
        iidd.instance_id = Some("i-02a44cb68978c43af".into());
        let mut guest = GuestFacts::default();
        guest.os = Some("StageX".into());
        guest.kernel = Some("7.2.0".into());
        snp.tsme = Some(true);
        snp.debug_allowed = Some(false);
        snp.page_swap_disable = Some(true);
        let mut imds = ImdsFacts::default();
        imds.instance_id = Some("i-02a44cb68978c43af".into());
        let tree = build_tree(nitro, snp, imds, iidd, guest);
        let s = render_summary(&tree);
        assert!(s.starts_with("TRUST SUMMARY
"));
        for line in s.lines() {
            assert!(
                line.chars().count() <= 80,
                "line over 80: {line:?}"
            );
        }
        let line_for = |label: &str| {
            s.lines()
                .find(|l| l.contains(&format!(" {label} ")))
                .unwrap_or_else(|| panic!("missing {label} line"))
        };
        // Identity facts anchored to the AWS root (signed IIDD / NitroTPM).
        assert!(line_for("instance").contains("AWS"));
        assert!(line_for("account").contains("AWS"));
        assert!(line_for("region").contains("AWS"));
        assert!(line_for("account").contains("412541033472"));
        assert!(!line_for("account").contains("AWS account"));
        assert!(line_for("isolation").contains("AMD"));
        // Boot is the dual-vendor fact: AWS PCRs + AMD launch measurement.
        assert!(line_for("boot").contains("AWS AMD"));
        // Self-reported facts carry no vendor.
        assert!(line_for("os").contains("(self)"));
        // Cross-attestation binding footer.
        assert!(s.contains("binding: a fresh 32-byte nonce"));
        assert!(s.contains("--expert"));
    }

    #[test]
    fn summary_json_has_vendors() {
        let mut nitro = NitroFacts::default();
        nitro.ok = true;
        nitro.pcr_count = 24;
        let mut snp = SnpFacts::default();
        snp.report = true;
        snp.vlek_verified = Some(true);
        snp.amd_chain_ok = Some(true);
        snp.measurement = Some("a1b2c3d4e5f60718".into());
        let tree = build_tree(nitro, snp, ImdsFacts::default(), IiddFacts::default(), GuestFacts::default());
        let j: serde_json::Value =
            serde_json::from_str(&to_summary_json(&tree)).expect("summary json parses");
        let facts = j["facts"].as_array().expect("facts array");
        let boot = facts
            .iter()
            .find(|f| f["name"] == "boot")
            .expect("boot fact");
        let vendors: Vec<&str> = boot["vendors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(vendors, vec!["AWS", "AMD"]);
        assert_eq!(j["binding"].is_null(), true);
    }

    #[test]
    fn root_integrity_requires_pinned_policy() {
        let mut nitro = NitroFacts::default();
        nitro.ok = true;
        nitro.pcr_count = 24;
        nitro.policy_len = 3;
        let tree = build_tree(
            nitro,
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let software = &tree.branches[5];
        let ri = software
            .facts
            .iter()
            .find(|f| f.name == "Root Integrity (measured)")
            .expect("root integrity fact");
        assert_eq!(ri.verdict, Verdict::True);
        assert_eq!(fact_vendors(ri), vec!["AWS"]);
        // Without a pinned policy the same attested doc is not a guarantee.
        let mut nitro2 = NitroFacts::default();
        nitro2.ok = true;
        nitro2.pcr_count = 24;
        let tree2 = build_tree(
            nitro2,
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let ri2 = tree2
            .branches[5]
            .facts
            .iter()
            .find(|f| f.name == "Root Integrity (measured)")
            .expect("root integrity fact");
        assert_eq!(ri2.verdict, Verdict::Unknown);
        let s = render_summary(&tree2);
        let rootfs = s
            .lines()
            .find(|l| l.contains(" rootfs "))
            .expect("rootfs summary line");
        assert!(rootfs.contains("?"));
    }

    #[test]
    fn pcr_policy_file_loads() {
        // v1: bare index->value object (operator-captured baseline).
        let path = std::env::temp_dir().join("bootproof-test-pcr-policy.json");
        std::fs::write(&path, r#"{"4": "aabb", "17": "00ff"}"#).unwrap();
        let pol = load_pcr_policy_file(&path).unwrap();
        assert_eq!(pol.values.get(&4), Some(&vec![0xaa, 0xbb]));
        assert_eq!(pol.values.get(&17), Some(&vec![0x00, 0xff]));
        assert_eq!(pol.source, None);
        // v2: reproducible-build anchor with source provenance.
        std::fs::write(
            &path,
            r#"{"source": "sha256:abc123", "pcrs": {"4": "aabb"}}"#,
        )
        .unwrap();
        let pol2 = load_pcr_policy_file(&path).unwrap();
        assert_eq!(pol2.values.get(&4), Some(&vec![0xaa, 0xbb]));
        assert_eq!(pol2.source.as_deref(), Some("sha256:abc123"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn root_integrity_source_provenance_renders() {
        let mut nitro = NitroFacts::default();
        nitro.ok = true;
        nitro.pcr_count = 24;
        nitro.policy_len = 4;
        nitro.policy_source = Some("sha256:abc123".into());
        let tree = build_tree(
            nitro,
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let ri = tree
            .branches[5]
            .facts
            .iter()
            .find(|f| f.name == "Root Integrity (measured)")
            .expect("fact");
        assert!(ri
            .evidence
            .iter()
            .any(|e| e.detail.contains("DERIVED FROM SOURCE sha256:abc123")));
    }

    #[test]
    fn iidd_verified_upgrades_custody_to_true() {
        let mut iidd = IiddFacts::default();
        iidd.verified = true;
        iidd.account = Some("412541033472".into());
        iidd.instance_type = Some("c6a.large".into());
        iidd.region = Some("us-east-2".into());
        iidd.instance_id = Some("i-02a44cb68978c43af".into());
        iidd.cert_region = Some("us-east-2".into());
        let mut imds = ImdsFacts::default();
        imds.instance_id = Some("i-02a44cb68978c43af".into());
        let tree = build_tree(
            NitroFacts::default(),
            SnpFacts::default(),
            imds,
            iidd,
            GuestFacts::default(),
        );
        let custody = &tree.branches[1];
        let owner = custody
            .facts
            .iter()
            .find(|f| f.name == "Owner / Account")
            .expect("owner fact");
        assert_eq!(owner.verdict, Verdict::True);
        assert_eq!(owner.value, "AWS account 412541033472");
        let s = render(&tree);
        assert!(s.contains("c6a.large"));
    }

    #[test]
    fn provenance_branch_renders_when_present() {
        let prov = ProvenanceFacts {
            present: true,
            doc_name: Some("StageX build provenance (distro-enclave-dev-img)".into()),
            origin: Some("codeberg.org/stagex/stagex @ 6a618c0f9991d7b6 (branch lance/distros, dirty 0)".into()),
            packages: 217,
            digests: 215,
            relationships: 1651,
            error: None,
        };
        let tree = build_tree_with(
            NitroFacts::default(),
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
            &prov,
        );
        assert_eq!(tree.branches.len(), 7);
        let pb = &tree.branches[6];
        assert_eq!(pb.name, "Provenance");
        let f = &pb.facts[0];
        assert_eq!(f.verdict, Verdict::Unknown);
        assert!(f.evidence.iter().any(|e| e.detail.contains("6a618c0f9991d7b6")));
        assert!(f.evidence.iter().any(|e| e.detail.contains("215 SHA256 digests")));
        let s = render(&tree);
        assert!(s.contains("Source / Provenance"));
        let ssum = render_summary(&tree);
        assert!(ssum.contains("provenance"), "{ssum}");
    }

    #[test]
    fn provenance_branch_absent_by_default() {
        let tree = build_tree(
            NitroFacts::default(),
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        assert_eq!(tree.branches.len(), 6);
    }

    #[test]
    fn nitro_user_data_renders_as_aws_rooted_evidence() {
        let mut nitro = NitroFacts::default();
        nitro.ok = true;
        nitro.pcr_count = 24;
        nitro.user_data = Some(b"release=sha256:abc123".to_vec());
        let tree = build_tree(
            nitro,
            SnpFacts::default(),
            ImdsFacts::default(),
            IiddFacts::default(),
            GuestFacts::default(),
        );
        let tpm = tree
            .branches[4]
            .facts
            .iter()
            .find(|f| f.name == "TPM")
            .expect("tpm fact");
        assert_eq!(tpm.verdict, Verdict::True);
        assert!(tpm
            .evidence
            .iter()
            .any(|e| e.detail.contains("release=sha256:abc123")
                && e.detail.contains("pinned AWS root")
                && e.proof == Verdict::True));
    }
}
