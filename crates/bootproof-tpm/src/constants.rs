//! TPM 2.0 constants: command codes, algorithm identifiers, structure tags,
//! and resource handles. Values are from TPM 2.0 Part 2 (Structure and
//! Semantics), Table 4 (TPM_CC), Table 9 (TPM_ALG), Table 18 (TPM_ST), and
//! Table 42 (TPM_RH).

pub mod cc {
    // Command codes (TPM_CC). Values verified against the TPM 2.0 spec Table 4.
    pub const EVICT_CONTROL: u16 = 0x0120;
    pub const PCR_ALLOCATE: u16 = 0x012B;
    pub const CREATE_PRIMARY: u16 = 0x0131;
    pub const STARTUP: u16 = 0x0144;
    pub const CERTIFY: u16 = 0x0148;
    pub const CREATE: u16 = 0x0153;
    pub const ECDH_ZGEN: u16 = 0x0154;
    pub const QUOTE: u16 = 0x0158;
    pub const SIGN: u16 = 0x015D;
    pub const UNSEAL: u16 = 0x015E;
    pub const CONTEXT_LOAD: u16 = 0x0161;
    pub const CONTEXT_SAVE: u16 = 0x0162;
    pub const ECDH_KEYGEN: u16 = 0x0163;
    pub const FLUSH_CONTEXT: u16 = 0x0165;
    pub const READ_PUBLIC: u16 = 0x0173;
    pub const START_AUTH_SESSION: u16 = 0x0176;
    pub const VERIFY_SIGNATURE: u16 = 0x0177;
    pub const ECC_PARAMETERS: u16 = 0x0178;
    pub const GET_CAPABILITY: u16 = 0x017A;
    pub const GET_RANDOM: u16 = 0x017B;
    pub const GET_TEST_RESULT: u16 = 0x017C;
    pub const HASH: u16 = 0x017D;
    pub const PCR_READ: u16 = 0x017E;
    pub const POLICY_PCR: u16 = 0x017F;
    pub const POLICY_RESTART: u16 = 0x0180;
    pub const POLICY_GET_DIGEST: u16 = 0x0189;
    pub const PCR_EXTEND: u16 = 0x0182;
    pub const PCR_RESET: u16 = 0x0183;
    pub const NV_READ_PUBLIC: u16 = 0x0169;
}

pub mod alg {
    // Algorithm identifiers (TPM_ALG).
    pub const NULL: u16 = 0x0010;
    pub const SHA256: u16 = 0x000B;
    pub const SHA384: u16 = 0x000C;
    pub const SHA512: u16 = 0x000D;
    pub const AES: u16 = 0x0006;
    pub const CTR: u16 = 0x0040;
    pub const CFB: u16 = 0x0043;
    pub const ECDH: u16 = 0x001B;
    pub const ECDSA: u16 = 0x0018;
    pub const ECC: u16 = 0x0023;
    pub const KDF1_SP800_56A: u16 = 0x001C;
    pub const EC_P256: u16 = 0x0003;
    pub const EC_P384: u16 = 0x0015;
    pub const RSASSA: u16 = 0x0014;
    pub const RSAPSS: u16 = 0x0016;
}

pub mod st {
    // Structure tags (TPM_ST).
    pub const RSP_COMMAND: u16 = 0x00C4;
    pub const NULL: u16 = 0x8000;
    pub const NO_SESSIONS: u16 = 0x8001;
    pub const SESSIONS: u16 = 0x8002;
    pub const ATTEST_CERTIFY: u16 = 0x8017;
    pub const ATTEST_QUOTE: u16 = 0x8018;
    pub const ATTEST_TIME: u16 = 0x8019;
    pub const ATTEST_CREATION: u16 = 0x801A;
    pub const CREATION: u16 = 0x8021;
    pub const VERIFIED: u16 = 0x8022;
    pub const AUTH_SECRET: u16 = 0x8023;
    pub const HASHCHECK: u16 = 0x8024;
    pub const AUTH_SIGNED: u16 = 0x8025;
}

pub mod rh {
    // Reserved handle constants (TPM_RH), TPM 2.0 Part 2 Table 42. Values
    // verified against the TCG spec (microsoft/ms-tpm-20-ref
    // `TpmTypes.h`), upstream tpm2-tss, and the live NitroTPM.
    pub const OWNER: u32 = 0x4000_0001;
    pub const ENDORSEMENT: u32 = 0x4000_000B;
    pub const LOCKOUT: u32 = 0x4000_000A;
    pub const PLATFORM: u32 = 0x4000_000C;
    pub const PLATFORM_NV: u32 = 0x4000_000D;
    // The null (unbound) reserved handle.
    pub const NULL: u32 = 0x4000_0007;

    pub const EK_CERT_NV: u32 = 0x01C0_0002;
    pub const PLATFORM_CERT_NV: u32 = 0x01C0_000A;

    // First transient object handle.
    pub const TRANSIENT_FIRST: u32 = 0x8000_0000;
}

/// Handle type prefixes (TPM_HT), the high byte of a handle identifying its
/// kind. Used with GetCapability(TPMI_CAP_HANDLES) to enumerate loaded
/// handles.
pub mod ht {
    pub const TRANSIENT: u32 = 0x8000_0000;
    pub const PERSISTENT: u32 = 0x8100_0000;
    /// The full persistent-handle range (0x8100_0000..=0x81FF_FFFF).
    pub const PERSISTENT_RANGE: std::ops::RangeInclusive<u32> = 0x8100_0000..=0x81FF_FFFF;
    pub const LOADED_METADATA: u32 = 0x8200_0000;
    /// Session handle type (TPM_HT_SESSIONS), spec Part 2 Table 22: 0x02xxxxxx.
    /// HMAC=0x02, policy=0x03, trial=0x03.
    pub const SESSION: u32 = 0x0200_0000;
    pub const NV_INDEX: u32 = 0xB000_0000;
    pub const PERMANENT: u32 = 0x4000_0000;
}

/// GetCapability capability identifiers (TPMI_CAP), TCG Part 2 Table 30.
/// Verified against the Linux kernel (`TPM2_CAP_*`) and captured
/// `tpm2_getcap` request bytes.
pub mod cap {
    pub const ALGS: u32 = 0x0000_0000;
    pub const HANDLES: u32 = 0x0000_0001;
    pub const COMMANDS: u32 = 0x0000_0002;
    pub const PPS: u32 = 0x0000_0003;
    pub const PCR_PROPERTIES: u32 = 0x0000_0004;
    pub const PCRS: u32 = 0x0000_0005;
    pub const TPM_PROPERTIES: u32 = 0x0000_0006;
}

/// The magic value that prefixes every attestation structure (TPM2B_ATTEST).
pub const GENERATED_VALUE: u32 = 0xFF54_4347;

/// Return codes (TPM_RC) we care about.
pub mod rc {
    pub const SUCCESS: u16 = 0x0000;
    pub const FAILURE: u16 = 0x0001;
    pub const INITIALIZE: u16 = 0x0100;
    pub const VALUE: u16 = 0x0101;
    pub const NO_RESULT: u16 = 0x0108;
    pub const SIZE: u16 = 0x0111;
    pub const TAG: u16 = 0x0113;
    pub const INSUFFICIENT: u16 = 0x0140;
    pub const COMMAND_SIZE: u16 = 0x0144;
    pub const COMMAND_CODE: u16 = 0x0145;
    pub const INVALID_HANDLE: u16 = 0x0156;
    pub const AUTH_FAIL: u16 = 0x0132;
    pub const BAD_AUTH: u16 = 0x0136;
    pub const RETRY: u16 = 0x0150;
}
