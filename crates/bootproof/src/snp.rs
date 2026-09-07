//! Shared SEV-SNP primitives: one in-process path to a fresh firmware
//! attestation report from `/dev/sev-guest` (sev crate, `SNP_GET_EXT_REPORT`),
//! decoding the typed report, and anchoring it to AMD's root of trust.
//!
//! Three consumers, one implementation:
//! - the local trust tree (`trust` module) collects + anchors the report
//!   with a fresh in-process nonce;
//! - the node's `snp` channel (`attest::snp`) issues it per challenge, with
//!   the CLIENT's challenge nonce in report_data;
//! - the remote verifier (`verify::snp`) checks a report received over the
//!   wire against the same pinned roots.
//!
//! The AMD KDS chain is pinned at build time (fetched from
//! https://kdsintf.amd.com/vlek/v1/Milan/cert_chain on 2026-08-26; provenance
//! in `trust/data/README.md`): the platform-provisioned VLEK certificate
//! chains to the ASVK (SEV-VLEK-Milan) and ARK (ARK-Milan). The report
//! signature (ECDSA P-384 / SHA-384 over the first 672 report bytes) is
//! verified against that VLEK. All pure Rust (sev crypto_nossl): no snpguest,
//! no OpenSSL, no temp files, no `Command::new`.

use std::io::Cursor;
use std::path::Path;

use sev::certs::snp::{ca, Chain, Certificate, Verifiable};
use sev::firmware::guest::{AttestationReport, Firmware};
use sev::parser::{Decoder, Encoder};

/// The SEV-SNP guest char device.
pub const DEV_SEV_GUEST: &str = "/dev/sev-guest";

/// The AMD KDS chain for Milan VLEK, pinned at build time.
pub const AMD_ASVK_MILAN_PEM: &[u8] =
    include_bytes!("trust/data/asvk-sev-vlek-milan.pem");
pub const AMD_ARK_MILAN_PEM: &[u8] = include_bytes!("trust/data/ark-milan.pem");

/// Test fixture: a real 1184-byte firmware report captured from a live EC2
/// SEV-SNP guest (the same SNP_GET_EXT_REPORT ioctl `issue_report` issues
/// in-process), plus the 64-byte report_data that produced it and the live
/// VLEK certificate that signed it. The fixture's report_data front half is
/// the 32-byte challenge nonce the verifier binds on (`nonce_binding_ok`);
/// the report was captured at VMPL 1.
#[cfg(test)]
pub const FIXTURE_REPORT: &[u8] = include_bytes!("trust/data/snp-report-fixture.bin");
#[cfg(test)]
pub const FIXTURE_REQUEST: &[u8] = include_bytes!("trust/data/snp-request-fixture.bin");
#[cfg(test)]
pub const FIXTURE_VLEK_PEM: &[u8] = include_bytes!("trust/data/snp-vlek-fixture.pem");

/// The guest policy a memory-encrypted node must run: ABI 2.3, SMT allowed,
/// **debug disabled**, page-swap disabled (0x2030000). Anything else is not
/// a proof of a hardened CVM.
pub const POLICY_DEBUG_DISABLED: u64 = 0x2030_000;

/// The VMPL a memory-encrypted node must run at: the hypervisor (VMPL 1)
/// must not be able to observe or control the guest.
pub const REQUIRED_VMPL: u32 = 0;

/// A fresh extended report: the raw (v5, 1184-byte) report bytes, the typed
/// report, the certificate table the firmware returned, and the VLEK
/// certificate (when the firmware provisioned one).
pub struct ExtReport {
    pub report_bytes: Vec<u8>,
    pub report: AttestationReport,
    pub cert_table: Option<Vec<sev::firmware::host::CertTableEntry>>,
    pub vlek: Option<Certificate>,
}

/// Map the 32-byte challenge nonce into the 64-byte SNP report_data:
/// `nonce || 0x00 * 32`. The firmware echoes report_data inside the signed
/// report, so the challenge nonce is bound into the report exactly as the
/// tpm2 quote binds it (`qualifyingData == nonce`): one nonce covers both
/// channels, and the tpm2 slot link (PCR22 = H(concat of the other channels'
/// docs)) cross-links them at the TPM.
pub fn report_data_for_nonce(nonce: &[u8; 32]) -> [u8; 64] {
    let mut rd = [0u8; 64];
    rd[..32].copy_from_slice(nonce);
    rd
}

/// The nonce-binding check a verified snp report MUST satisfy: the 32-byte
/// challenge nonce is echoed verbatim in the first 32 bytes of the 64-byte
/// report_data (the back 32 bytes are firmware-chosen but integrity-covered
/// by the VLEK signature over the signed prefix), and the nonce is not
/// all-zero (an all-zero nonce would make the binding forgeable).
pub fn nonce_binding_ok(report_data: &[u8; 64], nonce: &[u8; 32]) -> bool {
    report_data[..32] == nonce[..] && nonce.iter().any(|&b| b != 0)
}

/// Is the SNP guest device present on this host? (QEMU dev boxes and
/// non-SNP hosts have no such device: the channel degrades to tpm2-only.)
pub fn device_present() -> bool {
    Path::new(DEV_SEV_GUEST).exists()
}

/// Issue `SNP_GET_EXT_REPORT` in-process against `/dev/sev-guest` with the
/// caller's 64-byte `report_data` (the challenge binding) and the requested
/// `vmpl` (must be >= the guest's current VMPL; the report echoes it), and
/// decode the typed report.
pub fn issue_report(report_data: [u8; 64], vmpl: u32) -> Result<ExtReport, String> {
    let mut fw = Firmware::open()
        .map_err(|e| format!("open {DEV_SEV_GUEST}: {e}"))?;
    let (report_bytes, cert_table) = fw
        .get_ext_report(Some(1), Some(report_data), Some(vmpl))
        .map_err(|e| format!("SNP_GET_EXT_REPORT: {e:?}"))?;
    let report = AttestationReport::decode(&mut Cursor::new(&report_bytes), ())
        .map_err(|e| format!("decode attestation report: {e:?}"))?;
    let vlek = cert_table
        .as_ref()
        .and_then(|t| {
            t.iter()
                .find(|c| c.cert_type == sev::firmware::host::CertType::VLEK)
                .map(|c| c.data.clone())
        })
        .and_then(|der| Certificate::from_der(&der).ok());
    Ok(ExtReport {
        report_bytes,
        report,
        cert_table,
        vlek,
    })
}

/// Decode the raw firmware report bytes into the typed report.
pub fn decode_report(report_bytes: &[u8]) -> Result<AttestationReport, String> {
    AttestationReport::decode(&mut Cursor::new(report_bytes), ())
        .map_err(|e| format!("decode attestation report: {e:?}"))
}

/// The result of anchoring a decoded report to AMD's root.
pub struct Checked {
    /// The guest policy (raw u64; 0x2030000 = debug-disabled baseline).
    pub policy: u64,
    /// The VMPL the guest runs at.
    pub vmpl: u32,
    /// The 64-byte report_data (what the challenge nonce must echo).
    pub report_data: [u8; 64],
    /// Whether the VLEK (P-384/SHA-384) signed the report.
    pub sig_ok: bool,
    /// Whether the VLEK -> ASVK (SEV-VLEK-Milan) -> ARK (ARK-Milan, pinned)
    /// chain verified.
    pub chain_ok: bool,
    /// A short reason when `chain_ok` is false.
    pub chain_err: Option<String>,
}

/// Check a decoded report against its VLEK: the firmware's report
/// signature (P-384/SHA-384) and the VLEK -> ASVK -> ARK chain against the
/// pinned roots. Policy/VMPL checks are pure comparisons, exposed here as
/// the typed values for the caller.
pub fn check(ar: &AttestationReport, vlek: &Certificate) -> Result<Checked, String> {
    // 1. Firmware report signature: the VLEK (ECDSA P-384 / SHA-384) signed
    //    the report; what `snpguest verify attestation` used to do.
    let sig_ok = (vlek, ar).verify().is_ok();

    // 2. AMD anchor: ARK-Milan self-signs, ARK signs the ASVK, the ASVK
    //    signed this live VLEK.
    let (chain_ok, chain_err) = match (
        Certificate::from_pem(AMD_ASVK_MILAN_PEM),
        Certificate::from_pem(AMD_ARK_MILAN_PEM),
    ) {
        (Ok(asvk), Ok(ark)) => {
            let chain = Chain {
                ca: ca::Chain { ark, ask: asvk },
                vek: vlek.clone(),
            };
            match (&chain).verify() {
                Ok(_) => (true, None),
                Err(e) => (
                    false,
                    Some(format!(
                        "VLEK does not chain to the pinned ARK-Milan: {e}"
                    )),
                ),
            }
        }
        (Err(e), _) => (false, Some(format!("pinned ASVK-Milan unreadable: {e:?}"))),
        (_, Err(e)) => (false, Some(format!("pinned ARK-Milan unreadable: {e:?}"))),
    };

    Ok(Checked {
        policy: ar.policy.0,
        vmpl: ar.vmpl,
        report_data: ar.report_data,
        sig_ok,
        chain_ok,
        chain_err,
    })
}

/// Encode a decoded report back to its canonical byte form (the form the
/// firmware signed: first 672 bytes).
pub fn encode_report(ar: &AttestationReport) -> Result<Vec<u8>, String> {
    let mut v = Vec::new();
    ar.encode(&mut v, ())
        .map_err(|e| format!("encode attestation report: {e:?}"))?;
    Ok(v)
}

/// The raw report bytes the VLEK signs (first 672 = 0x2a0 bytes).
pub fn signed_prefix(report_bytes: &[u8]) -> &[u8] {
    &report_bytes[..std::cmp::min(report_bytes.len(), 0x2a0)]
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &[u8] = include_bytes!("trust/data/snp-report-fixture.bin");
    const REQUEST: &[u8] = include_bytes!("trust/data/snp-request-fixture.bin");
    const VLEK: &[u8] = include_bytes!("trust/data/snp-vlek-fixture.pem");

    /// The fixture's report_data was the full 64-byte nonce the pre-channel
    /// trust path sent; the node channel now sends `nonce || 0x00*32`, and
    /// the verifier binds on the front 32 bytes.
    #[test]
    fn shared_decode_matches_fixture_nonce() {
        let ar = decode_report(REPORT).expect("fixture decodes");
        assert_eq!(
            &ar.report_data[..32],
            &REQUEST[..32],
            "report_data front half must echo the challenge nonce"
        );
        assert_eq!(ar.version, 5);
    }

    #[test]
    fn shared_check_anchors_fixture_to_amd_root() {
        let ar = decode_report(REPORT).unwrap();
        let vlek = Certificate::from_pem(VLEK).unwrap();
        let c = check(&ar, &vlek).unwrap();
        assert_eq!(c.policy, 0x2030000);
        assert_eq!(c.vmpl, 1, "the fixture was captured at VMPL 1");
        assert_eq!(&c.report_data[..32], &REQUEST[..32]);
        assert!(c.sig_ok, "VLEK signed the firmware report");
        assert!(c.chain_ok, "VLEK chains to the pinned ARK-Milan");
        assert!(c.chain_err.is_none());
    }

    #[test]
    fn shared_check_rejects_wrong_signer() {
        // The fixture report was signed by the fixture VLEK. A different
        // cert must fail the report signature check.
        let ar = decode_report(REPORT).unwrap();
        let other = Certificate::from_pem(AMD_ASVK_MILAN_PEM).unwrap();
        let c = check(&ar, &other).unwrap();
        assert!(!c.sig_ok, "a non-signing cert must not verify the report");
    }

    #[test]
    fn shared_check_rejects_unanchored_cert() {
        // A cert that cannot anchor a VLEK: the chain check must fail with a
        // reason (the "present but not anchored" case). The pinned ARK is a
        // self-signed RSA-PSS root, not a VLEK, so it cannot have signed the
        // fixture VLEK -- the chain must reject it.
        let ar = decode_report(REPORT).unwrap();
        let ark = Certificate::from_pem(AMD_ARK_MILAN_PEM).unwrap();
        let c = check(&ar, &ark).unwrap();
        assert!(!c.chain_ok, "the ARK is not a VLEK and cannot anchor one");
        assert!(c.chain_err.is_some(), "a failed chain must carry a reason");
    }

    #[test]
    fn shared_encode_matches_firmware_bytes() {
        // The typed report must round-trip to the exact bytes the firmware
        // produced (what the VLEK signed).
        let ar = decode_report(REPORT).unwrap();
        let encoded = encode_report(&ar).unwrap();
        assert_eq!(encoded, REPORT, "encode must be byte-identical to the firmware report");
    }
}
