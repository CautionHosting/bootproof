//! ESYS backend: a thin Rust wrapper over the platform's tss2 C stack
//! (the ESAPI), linking the device TCTI directly instead of going through
//! the TCTI loader. No plugin dlopen is needed, so the resulting binary
//! can be fully static and still talk to a hardware TPM.
//!
//! The StageX / NitroTPM firmware speaks a renumbered TPM2 dialect:
//! endorsement hierarchy `0x4000000B` (standard `0x40000003`), symmetric
//! CFB `0x0043` (standard `0x0045`), and shifted `TPMA_OBJECT` bits. The
//! dialect is detected at open time via `TPM2_GetCapability` and the
//! matching constants are marshaled. Standard TPMs (e.g. swtpm) take the
//! spec-conformant path.
//!
//! All calls go through the tss2 C libraries (`tss-esapi-sys` bindings),
//! which carry the platform's own session framing and marshaling.

use std::ffi::{c_void, CString};
use std::mem;
use std::os::raw::c_char;
use std::path::Path;

use tss_esapi_sys as sys;

use digest::Digest;
use sha2::Sha256;

use crate::commands::{PcrReadResult, PcrSelection, PcrValue};
use crate::commands_key::{Key, Quote};
use crate::constants::alg;
use crate::error::{Error, Result};

/// A sealed data object (TPM_ALG_KEYEDHASH with exclusiveOR, or an
/// auth-only data blob) produced by `create_data_object`. `private` is the
/// TPM-wrapped sensitive (unsealable only under the parent); `public` is the
/// `TPMT_PUBLIC` wire bytes; `name` is the object's Name.
#[derive(Debug, Clone)]
pub struct DataObject {
    /// Transient handle after `load_data_object` (0 before it).
    pub handle: u32,
    /// TPM2B_PRIVATE buffer (the wrapped sensitive data).
    pub private: Vec<u8>,
    /// TPMT_PUBLIC wire bytes (dialect Tss2_MU marshal of the public area).
    pub public: Vec<u8>,
    /// The object's Name (TPM2B_NAME buffer).
    pub name: Vec<u8>,
}

/// Standard (spec) TPM_RH hierarchy handles.
pub mod rh_std {
    pub const OWNER: u32 = 0x4000_0001;
    pub const ENDORSEMENT: u32 = 0x4000_0003;
    pub const PLATFORM: u32 = 0x4000_0004;
    pub const EK: u32 = 0x4000_0006;
    pub const NULL: u32 = 0x4000_0007;
    pub const LOCKOUT: u32 = 0x4000_0009;
}

/// Dialect (StageX / NitroTPM) TPM_RH hierarchy handles.
pub mod rh_dialect {
    pub const OWNER: u32 = 0x4000_0001;
    pub const TRANSPORT: u32 = 0x4000_0003;
    pub const EK: u32 = 0x4000_0006;
    pub const NULL: u32 = 0x4000_0007;
    pub const LOCKOUT: u32 = 0x4000_000A;
    pub const ENDORSEMENT: u32 = 0x4000_000B;
    pub const PLATFORM: u32 = 0x4000_000C;
}

/// Map a standard `TPM_RH` hierarchy to its tss2 `ESYS_TR` handle. The
/// StageX tss2 build translates `ESYS_TR_RH_*` to the firmware's wire
/// values (renumbered in the dialect), so this is the only mapping the
/// client needs.
fn hierarchy_to_esys_tr(hierarchy: u32) -> u32 {
    match hierarchy {
        rh_std::OWNER => sys::ESYS_TR_RH_OWNER,
        rh_std::ENDORSEMENT | rh_dialect::ENDORSEMENT => sys::ESYS_TR_RH_ENDORSEMENT,
        rh_std::PLATFORM | rh_dialect::PLATFORM => sys::ESYS_TR_RH_PLATFORM,
        rh_std::NULL => sys::ESYS_TR_RH_NULL,
        other => other,
    }
}

// --- algorithm / scheme constants (identical in both dialects) -----------

const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const ECC_NIST_P256: u16 = 0x0003;

// TPM2_SE: standard HMAC=0x00, EXPLICIT=0x01, POLICY=0x02, TRIAL=0x03.
// Dialect (StageX tss2 header): HMAC=0x00, POLICY=0x01, TRIAL=0x03.
const TPM_SE_TRIAL: u8 = 0x03;
const TPM_SE_POLICY_STD: u8 = 0x02;
const TPM_SE_POLICY_DIALECT: u8 = 0x01;

// --- dialect-divergent constants ------------------------------------------

const SYM_MODE_CFB_STD: u16 = 0x0045;
const SYM_MODE_CFB_DIALECT: u16 = 0x0043;

/// Standard `TPMA_OBJECT`: fixedTPM | fixedParent | sensitiveDataOrigin |
/// userWithAuth | noDA | restricted | signEncrypt.
const OBJ_ATTRS_SIGN_STD: u32 =
    0x0000_0001 | 0x0000_0004 | 0x0000_0008 | 0x0000_0010 | 0x0000_0200 | 0x0000_8000 | 0x0002_0000;

/// Dialect `TPMA_OBJECT` (per the platform header: low 16 bits shifted one
/// vs. spec, high bits standard): fixedTPM(0x2) | fixedParent(0x10) |
/// sensitiveDataOrigin(0x20) | userWithAuth(0x40) | restricted(0x10000) |
/// signEncrypt(0x40000). Setting 0x100000/0x400000 (RESERVED5) or noDA
/// (0x400) makes the firmware reject the template with 0x2E1
/// ("parameter(2): reserved bits not set to zero").
const OBJ_ATTRS_SIGN_DIALECT: u32 =
    0x0000_0002 | 0x0000_0010 | 0x0000_0020 | 0x0000_0040 | 0x0001_0000 | 0x0004_0000;

const TPM2_SU_CLEAR: u16 = 0x0000;
const TPM2_SU_STATE: u16 = 0x0001;
const TPM2_SE_HMAC: u8 = 0x0001;
const TPM2_CAP_ALGORITHMS: u32 = 0x0000;

// --- data-object (TPM_ALG_KEYEDHASH exclusiveOr) constants -----------------

/// XOR keyedHash scheme selector (dialect `TPM2_ALG_XOR`).
const TPM_ALG_XOR: u16 = 0x000A;
/// KDF1 (SP800-56A) for the exclusiveOr scheme (dialect `TPM2_ALG_KDF1_SP800_56A`).
const TPM_ALG_KDF1_SP800_56A: u16 = 0x0020;
/// KDF2 for the exclusiveOr scheme (dialect `TPM2_ALG_KDF2`).
const TPM_ALG_KDF2: u16 = 0x0021;
/// Dialect `TPMA_OBJECT` for a caller-provided sealed data object:
/// fixedTPM(0x2) | fixedParent(0x10) | userWithAuth(0x40).
/// sensitiveDataOrigin is 0 (the caller supplies the data); noDA is not set
/// (the firmware rejects 0x400, 0x2E1).
const OBJ_ATTRS_DATA_DIALECT: u32 = 0x0000_0012 | 0x0000_0040;

// Device TCTI entry point (from `tss2_tcti_device.h`; not in the
// pre-generated bindings). This tss2 build predates the finalize API:
// the context is caller-allocated (size probe, then init) and released
// via the context's own finalize hook.
unsafe extern "C" {
    fn Tss2_Tcti_Device_Init(
        tcti_context: *mut sys::TSS2_TCTI_CONTEXT,
        size: *mut usize,
        conf: *const c_char,
    ) -> u32;
    // Dialect RC decoder (libtss2-rc, already linked). Returns a static string.
    fn Tss2_RC_Decode(rc: u32) -> *const c_char;
    // Command-logging / dialect-shim trampoline (trampoline.c, built by
    // build.rs).
    fn bp_tx_set_orig(fn_ptr: *mut c_void);
    fn bp_rx_set_orig(fn_ptr: *mut c_void);
    fn bp_set_log(enabled: i32);
    // Must match sys::TSS2_TCTI_TRANSMIT_FCN exactly (size_t = u64).
    fn bp_tx(ctx: *mut sys::TSS2_TCTI_CONTEXT, size: u64, buffer: *const u8) -> u32;
    fn bp_rx(
        ctx: *mut sys::TSS2_TCTI_CONTEXT,
        size: *mut u64,
        buffer: *mut u8,
        timeout: i32,
    ) -> u32;
}

fn check(rc: u32, what: &str) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "{what}: tss2 RC 0x{rc:08x} ({})",
            decode_rc(rc)
        )))
    }
}

/// Decode a tss2 RC through the DIALECT's own RC decoder (libtss2-rc).
/// This is the authoritative name for the platform firmware's error codes.
pub fn decode_rc(rc: u32) -> String {
    let p = unsafe { Tss2_RC_Decode(rc) };
    if p.is_null() {
        return String::new();
    }
    let mut s = String::new();
    let mut i = 0usize;
    unsafe {
        while *p.add(i) != 0 {
            s.push(*p.add(i) as u8 as char);
            i += 1;
        }
    }
    s
}

fn pcr_selection_list(selections: &[PcrSelection]) -> sys::TPML_PCR_SELECTION {
    let mut list: sys::TPML_PCR_SELECTION = unsafe { mem::zeroed() };
    for (i, s) in selections.iter().enumerate().take(16) {
        list.pcrSelections[i].hash = s.hash;
        list.pcrSelections[i].sizeofSelect = 3;
        list.pcrSelections[i].pcrSelect[..3].copy_from_slice(&s.pcr_select);
    }
    list.count = selections.len().min(16) as u32;
    list
}

fn ecdsa_sha256_scheme() -> sys::TPMT_SIG_SCHEME {
    sys::TPMT_SIG_SCHEME {
        scheme: TPM_ALG_ECDSA,
        details: sys::TPMU_SIG_SCHEME {
            ecdsa: sys::TPMS_SCHEME_HASH {
                hashAlg: TPM_ALG_SHA256,
            },
        },
    }
}

/// The `TPMT_PUBLIC` template for an ECC P-256 ECDSA/SHA-256 signing key
/// with empty auth and no auth policy, in the requested dialect.
fn build_ecc_sign_public(dialect: bool) -> sys::TPM2B_PUBLIC {
    let mut tp: sys::TPMT_PUBLIC = unsafe { mem::zeroed() };
    tp.type_ = TPM_ALG_ECC;
    tp.nameAlg = TPM_ALG_SHA256;
    tp.objectAttributes = if dialect {
        OBJ_ATTRS_SIGN_DIALECT
    } else {
        OBJ_ATTRS_SIGN_STD
    };
    unsafe {
        tp.parameters.eccDetail = sys::TPMS_ECC_PARMS {
            symmetric: if dialect {
                // The dialect firmware rejects AES symmetric on ECC keys
                // ("unsupported symmetric algorithm ... not appropriate for
                // instance", 0x2D6); NULL is required.
                sys::TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM_ALG_NULL,
                    keyBits: mem::zeroed(),
                    mode: mem::zeroed(),
                }
            } else {
                sys::TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM_ALG_AES,
                    keyBits: sys::TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: sys::TPMU_SYM_MODE {
                        aes: SYM_MODE_CFB_STD,
                    },
                }
            },
            scheme: sys::TPMT_ECC_SCHEME {
                scheme: TPM_ALG_ECDSA,
                details: sys::TPMU_ASYM_SCHEME {
                    ecdsa: sys::TPMS_SCHEME_HASH {
                        hashAlg: TPM_ALG_SHA256,
                    },
                },
            },
            curveID: ECC_NIST_P256,
            kdf: sys::TPMT_KDF_SCHEME {
                scheme: TPM_ALG_NULL,
                details: mem::zeroed(),
            },
        };
        // Empty unique: the TPM generates the key pair.
        tp.unique.ecc = sys::TPMS_ECC_POINT {
            x: sys::TPM2B_ECC_PARAMETER {
                size: 0,
                buffer: [0u8; 128],
            },
            y: sys::TPM2B_ECC_PARAMETER {
                size: 0,
                buffer: [0u8; 128],
            },
        };
    }
    let mut pub2b = sys::TPM2B_PUBLIC {
        size: 0,
        publicArea: tp,
    };
    let mut written: u64 = 0;
    let mut scratch = vec![0u8; mem::size_of::<sys::TPMT_PUBLIC>()];
    if unsafe {
        sys::Tss2_MU_TPMT_PUBLIC_Marshal(
            &tp,
            scratch.as_mut_ptr(),
            scratch.len() as u64,
            &mut written,
        )
    } == 0
    {
        pub2b.size = written as u16;
    }
    pub2b
}

/// The `TPMT_PUBLIC` template for an RSA 2048 restricted-decrypt key
/// (empty auth, no policy): AES-128 symmetric, OAEP/SHA-256 scheme,
/// default exponent. The dialect tss2 `Tss2_MU_TPMT_PUBLIC_Marshal`
/// decides the on-wire field layout (see `marshal_public_bytes`).
pub fn build_rsa_decrypt_public() -> sys::TPMT_PUBLIC {
    let mut tp: sys::TPMT_PUBLIC = unsafe { mem::zeroed() };
    tp.type_ = 0x0001; // TPM_ALG_RSA
    tp.nameAlg = TPM_ALG_SHA256;
    tp.objectAttributes = 0x0003_0072; // fixedtpm|fixedparent|sdorigin|userwithauth|restricted|decrypt
    unsafe {
        tp.parameters.rsaDetail = sys::TPMS_RSA_PARMS {
            symmetric: sys::TPMT_SYM_DEF_OBJECT {
                algorithm: TPM_ALG_AES,
                keyBits: sys::TPMU_SYM_KEY_BITS { aes: 128 },
                mode: sys::TPMU_SYM_MODE { aes: 0x0043 }, // CFB
            },
            // A restricted decryption key REQUIRES scheme = NULL
            // (OAEP is only valid for unrestricted decrypt keys); the
            // firmware rejects OAEP here.
            scheme: sys::TPMT_RSA_SCHEME {
                scheme: TPM_ALG_NULL,
                details: mem::zeroed(),
            },
            keyBits: 2048,
            exponent: 0, // default 65537
        };
        // Empty unique: the TPM generates the key.
        tp.unique.rsa = sys::TPM2B_PUBLIC_KEY_RSA {
            size: 0,
            buffer: [0u8; 512],
        };
    }
    tp
}

/// Marshal a `TPMT_PUBLIC` to its dialect wire bytes (public API for
/// experiments; the dialect tss2 marshaller is the layout authority).
pub fn marshal_public_bytes(tp: &sys::TPMT_PUBLIC) -> Result<Vec<u8>> {
    marshal_public(tp)
}

/// Marshal a `TPMT_PUBLIC` to its wire bytes.
fn marshal_public(public_area: &sys::TPMT_PUBLIC) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; mem::size_of::<sys::TPMT_PUBLIC>()];
    let mut written: u64 = 0;
    let rc = unsafe {
        sys::Tss2_MU_TPMT_PUBLIC_Marshal(
            public_area,
            buf.as_mut_ptr(),
            buf.len() as u64,
            &mut written,
        )
    };
    check(rc, "Tss2_MU_TPMT_PUBLIC_Marshal")?;
    buf.truncate(written as usize);
    Ok(buf)
}

/// Marshal a `TPMS_SENSITIVE_CREATE` to its significant wire bytes (the
/// `Tss2_MU` marshaller is the layout authority; used to size the
/// `TPM2B_SENSITIVE_CREATE.size` field, which is written verbatim to the wire).
fn marshal_sensitive_create(s: &sys::TPMS_SENSITIVE_CREATE) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; mem::size_of::<sys::TPMS_SENSITIVE_CREATE>()];
    let mut written: u64 = 0;
    let rc = unsafe {
        sys::Tss2_MU_TPMS_SENSITIVE_CREATE_Marshal(
            s,
            buf.as_mut_ptr(),
            buf.len() as u64,
            &mut written,
        )
    };
    check(rc, "Tss2_MU_TPMS_SENSITIVE_CREATE_Marshal")?;
    buf.truncate(written as usize);
    Ok(buf)
}

/// Dialect HMAC keyedHash scheme selector (TPM2_ALG_HMAC).
const TPM_ALG_HMAC: u16 = 0x0005;

/// A `TPMT_PUBLIC` template for a `TPM_ALG_KEYEDHASH` data object with the
/// requested scheme (dialect attributes, SHA-256 name, empty unique so the
/// TPM derives the Name). `kdf` applies only to the XOR scheme; `hmac`
/// uses the SHA-256 scheme; `null` uses no scheme.
pub fn build_keyedhash_public(scheme: u16, kdf: u16, policy_digest: &[u8]) -> sys::TPMT_PUBLIC {
    let mut tp: sys::TPMT_PUBLIC = unsafe { mem::zeroed() };
    tp.type_ = TPM_ALG_KEYEDHASH;
    tp.nameAlg = TPM_ALG_SHA256;
    tp.objectAttributes = OBJ_ATTRS_DATA_DIALECT;
    // authPolicy: empty for auth-only objects, else the bound policy digest.
    let ap = policy_digest.len().min(64);
    tp.authPolicy.size = ap as u16;
    tp.authPolicy.buffer[..ap].copy_from_slice(&policy_digest[..ap]);
    let scheme_details: sys::TPMU_SCHEME_KEYEDHASH = unsafe { mem::zeroed() };
    tp.parameters.keyedHashDetail = sys::TPMS_KEYEDHASH_PARMS {
        scheme: sys::TPMT_KEYEDHASH_SCHEME {
            scheme,
            details: scheme_details,
        },
    };
    if scheme == TPM_ALG_XOR {
        // The firmware rejects XOR keyedHash (0x2D2); kept for completeness.
        unsafe {
            tp.parameters.keyedHashDetail.scheme.details.exclusiveOr = sys::TPMS_SCHEME_XOR {
                hashAlg: TPM_ALG_SHA256,
                kdf,
            };
        }
    }
    if scheme == TPM_ALG_HMAC {
        unsafe {
            tp.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
        }
    }
    // Empty unique (TPM2B_DIGEST size 0): the keyedHash has no public part.
    tp
}

/// A TPM connection backed by the tss2 ESAPI (C stack) with a directly
/// linked device TCTI.
///
/// Mirrors the method surface of the raw [`crate::Tpm`] so the two
/// backends can be swapped without touching the SDK.
pub struct EsysTpm {
    tcti: Vec<u8>,
    esys: *mut sys::ESYS_CONTEXT,
    dialect: bool,
}

impl EsysTpm {
    /// Allocate and initialize the device TCTI context. This tss2 build
    /// uses the caller-allocated API: probe with a null context to get the
    /// required size, then init caller memory of that size.
    fn init_device_tcti(conf: &CString) -> Result<Vec<u8>> {
        let mut size: usize = 0;
        unsafe {
            let rc = Tss2_Tcti_Device_Init(std::ptr::null_mut(), &mut size, conf.as_ptr());
            check(rc, "Tss2_Tcti_Device_Init(size probe)")?;
        }
        if size == 0 {
            return Err(Error::Other(
                "Tss2_Tcti_Device_Init reported context size 0".into(),
            ));
        }
        let mut tcti = vec![0u8; size];
        unsafe {
            let rc = Tss2_Tcti_Device_Init(
                tcti.as_mut_ptr() as *mut sys::TSS2_TCTI_CONTEXT,
                &mut size,
                conf.as_ptr(),
            );
            check(rc, "Tss2_Tcti_Device_Init")?;
        }
        Ok(tcti)
    }

    /// Invoke the context's finalize hook (closes the device file
    /// descriptor); the buffer itself is dropped by the caller.
    fn finalize_device_tcti(tcti: &mut Vec<u8>) {
        unsafe {
            let common = tcti.as_mut_ptr() as *mut sys::TSS2_TCTI_CONTEXT_COMMON_V1;
            if let Some(finalize) = (*common).finalize {
                let _ = finalize(tcti.as_mut_ptr() as *mut sys::TSS2_TCTI_CONTEXT);
            }
        }
    }

    /// Open a TPM device node through the device TCTI and initialize the
    /// ESAPI context.
    pub fn open(path: &Path) -> Result<Self> {
        let conf = CString::new(path.to_string_lossy().as_ref())
            .map_err(|_| Error::Other("device path is not valid UTF-8".into()))?;
        let mut tcti = Self::init_device_tcti(&conf)?;
        let mut esys: *mut sys::ESYS_CONTEXT = std::ptr::null_mut();
        unsafe {
            let rc = sys::Esys_Initialize(
                &mut esys,
                tcti.as_mut_ptr() as *mut sys::TSS2_TCTI_CONTEXT,
                std::ptr::null_mut(),
            );
            if rc != 0 {
                Self::finalize_device_tcti(&mut tcti);
                return Err(Error::Other(format!(
                    "Esys_Initialize: tss2 RC 0x{rc:08x}"
                )));
            }
        }
        let mut tpm = Self {
            tcti,
            esys,
            dialect: false,
        };
        // Dialect shim: the StageX esys stack emits a non-zero SAS
        // sessionAttributes byte that the firmware rejects; the trampoline
        // zeroes it. Also enables hex logging under BP_LOG_TCTI.
        tpm.install_command_logger();
        tpm.dialect = tpm.detect_dialect();
        Ok(tpm)
    }

    /// Install the TCTI transmit/receive trampoline (dialect shim +
    /// optional hex dump to stderr under BP_LOG_TCTI=1).
    fn install_command_logger(&mut self) {
        unsafe {
            let common = self.tcti.as_mut_ptr() as *mut sys::TSS2_TCTI_CONTEXT_COMMON_V1;
            let orig = (*common).transmit.expect("tcti has no transmit hook");
            bp_tx_set_orig(orig as *mut _);
            (*common).transmit = Some(bp_tx);
            let orig_rx = (*common).receive.expect("tcti has no receive hook");
            bp_rx_set_orig(orig_rx as *mut _);
            (*common).receive = Some(bp_rx);
            bp_set_log(if std::env::var("BP_LOG_TCTI").is_ok() { 1 } else { 0 });
        }
    }

    /// True when the firmware uses the renumbered TPM2 dialect (detected
    /// by advertising symmetric mode `0x43`, which the spec does not
    /// define as an algorithm).
    pub fn dialect(&self) -> bool {
        self.dialect
    }

    fn detect_dialect(&mut self) -> bool {
        unsafe {
            let mut more: u8 = 0;
            let mut cap: *mut sys::TPMS_CAPABILITY_DATA = std::ptr::null_mut();
            let rc = sys::Esys_GetCapability(
                self.esys,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                TPM2_CAP_ALGORITHMS,
                SYM_MODE_CFB_DIALECT as u32,
                1,
                &mut more,
                &mut cap,
            );
            if rc != 0 || cap.is_null() {
                return false;
            }
            let supported = (*cap).data.algorithms.count > 0;
            sys::Esys_Free(cap as *mut _);
            supported
        }
    }

    /// Ensure the TPM is started (mirrors `Tpm::ensure_started`).
    pub fn ensure_started(&mut self) -> Result<()> {
        let probe = [PcrSelection::new(alg::SHA256, &[0])];
        if self.pcr_read(&probe).is_ok() {
            return Ok(());
        }
        // Prefer STATE (preserves PCRs); fall back to CLEAR.
        let rc = unsafe { sys::Esys_Startup(self.esys, TPM2_SU_STATE) };
        if rc != 0 {
            let rc = unsafe { sys::Esys_Startup(self.esys, TPM2_SU_CLEAR) };
            check(rc, "Esys_Startup(CLEAR)")?;
        }
        self.pcr_read(&probe).map(|_| ())
    }

    /// TPM2_GetRandom.
    pub fn get_random(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < n {
            let want = std::cmp::min(32, n - out.len());
            unsafe {
                let mut data: *mut sys::TPM2B_DIGEST = std::ptr::null_mut();
                let rc = sys::Esys_GetRandom(
                    self.esys,
                    sys::ESYS_TR_NONE,
                    sys::ESYS_TR_NONE,
                    sys::ESYS_TR_NONE,
                    want as u16,
                    &mut data,
                );
                check(rc, "Esys_GetRandom")?;
                let d = &*data;
                out.extend_from_slice(&d.buffer[..d.size as usize]);
                sys::Esys_Free(data as *mut _);
            }
        }
        Ok(out)
    }

    /// Start a null-auth HMAC session bound to the NULL hierarchy (the
    /// session framing tpm2-tools on this platform uses).
    fn start_nullauth_session(&mut self) -> Result<u32> {
        let nonce_bytes = self.get_random(32)?;
        let mut nonce: sys::TPM2B_NONCE = unsafe { mem::zeroed() };
        nonce.size = nonce_bytes.len() as u16;
        nonce.buffer[..nonce.size as usize].copy_from_slice(&nonce_bytes);
        unsafe {
            let mut session: u32 = 0;
            let sym: sys::TPMT_SYM_DEF = sys::TPMT_SYM_DEF {
                algorithm: TPM_ALG_NULL,
                keyBits: mem::zeroed(),
                mode: mem::zeroed(),
            };
            let rc = sys::Esys_StartAuthSession(
                self.esys,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_RH_NULL,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &nonce,
                TPM2_SE_HMAC,
                &sym,
                TPM_ALG_SHA256,
                &mut session,
            );
            check(rc, "Esys_StartAuthSession")?;
            Ok(session)
        }
    }

    /// Flush one loaded session (policy sessions live at `0x03xxxxxx`,
    /// so callers release them explicitly).
    pub fn flush_session(&mut self, session: u32) {
        unsafe {
            let _ = sys::Esys_FlushContext(self.esys, session);
        }
    }

    /// TPM2_CreatePrimary: create an ECC P-256 signing key in the given
    /// standard hierarchy. The tss2 build maps the `ESYS_TR` handle to the
    /// firmware's wire value (renumbered in the dialect).
    pub fn create_primary(&mut self, hierarchy: u32) -> Result<Key> {
        let in_public = build_ecc_sign_public(self.dialect);
        self.create_primary_with_public(hierarchy, &in_public.publicArea)
    }

    /// Create a **storage** primary (RSA-2048 restricted+decrypt, the proven
    /// decrypt template). A child object created under a signing primary is
    /// rejected by the firmware with 0x18A ("handle(1): the type of the value
    /// is not appropriate for the use") — the parent must be a storage key.
    pub fn create_storage_primary(&mut self, hierarchy: u32) -> Result<Key> {
        self.create_primary_with_public(hierarchy, &build_rsa_decrypt_public())
    }

    /// TPM2_CreatePrimary with a caller-supplied `TPMT_PUBLIC` template.
    pub fn create_primary_with_public(
        &mut self,
        hierarchy: u32,
        in_public: &sys::TPMT_PUBLIC,
    ) -> Result<Key> {
        let primary_handle = hierarchy_to_esys_tr(hierarchy);
        let in_public2b = {
            let mut pub2b = sys::TPM2B_PUBLIC {
                size: 0,
                publicArea: *in_public,
            };
            let mut written: u64 = 0;
            let mut scratch = vec![0u8; mem::size_of::<sys::TPMT_PUBLIC>()];
            if unsafe {
                sys::Tss2_MU_TPMT_PUBLIC_Marshal(
                    in_public,
                    scratch.as_mut_ptr(),
                    scratch.len() as u64,
                    &mut written,
                )
            } == 0
            {
                pub2b.size = written as u16;
            }
            pub2b
        };
        unsafe {
            let in_sensitive: sys::TPM2B_SENSITIVE_CREATE = mem::zeroed();
            let outside_info: sys::TPM2B_DATA = mem::zeroed();
            let creation_pcr: sys::TPML_PCR_SELECTION = mem::zeroed();
            let session = self.start_nullauth_session()?;
            let mut handle: u32 = 0;
            let mut out_public: *mut sys::TPM2B_PUBLIC = std::ptr::null_mut();
            let mut creation_data: *mut sys::TPM2B_CREATION_DATA = std::ptr::null_mut();
            let mut creation_hash: *mut sys::TPM2B_DIGEST = std::ptr::null_mut();
            let mut creation_ticket: *mut sys::TPMT_TK_CREATION = std::ptr::null_mut();
            let rc = sys::Esys_CreatePrimary(
                self.esys,
                primary_handle,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &in_sensitive,
                &in_public2b,
                &outside_info,
                &creation_pcr,
                &mut handle,
                &mut out_public,
                &mut creation_data,
                &mut creation_hash,
                &mut creation_ticket,
            );
            if rc != 0 {
                self.flush_session(session);
                return Err(Error::Other(format!(
                    "Esys_CreatePrimary (hierarchy 0x{primary_handle:08x}): \
                     tss2 RC 0x{rc:08x}"
                )));
            }
            let public = marshal_public(&(*out_public).publicArea);
            let mut name: Vec<u8> = Vec::new();
            if public.is_ok() {
                let mut name_ptr: *mut sys::TPM2B_NAME = std::ptr::null_mut();
                let rc = sys::Esys_TR_GetName(self.esys, handle, &mut name_ptr);
                if rc == 0 {
                    let n = &*name_ptr;
                    name = n.name[..n.size as usize].to_vec();
                    sys::Esys_Free(name_ptr as *mut _);
                }
            }
            sys::Esys_Free(out_public as *mut _);
            sys::Esys_Free(creation_data as *mut _);
            sys::Esys_Free(creation_hash as *mut _);
            sys::Esys_Free(creation_ticket as *mut _);
            self.flush_session(session);
            let public = public?;
            Ok(Key {
                handle,
                public,
                name,
            })
        }
    }

    /// TPM2_ReadPublic.
    pub fn read_public(&mut self, handle: u32) -> Result<Key> {
        unsafe {
            let mut out_public: *mut sys::TPM2B_PUBLIC = std::ptr::null_mut();
            let mut name: *mut sys::TPM2B_NAME = std::ptr::null_mut();
            let mut qualified_name: *mut sys::TPM2B_NAME = std::ptr::null_mut();
            let rc = sys::Esys_ReadPublic(
                self.esys,
                handle,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &mut out_public,
                &mut name,
                &mut qualified_name,
            );
            check(rc, "Esys_ReadPublic")?;
            let public = marshal_public(&(*out_public).publicArea);
            let n = &*name;
            let name_bytes = n.name[..n.size as usize].to_vec();
            sys::Esys_Free(out_public as *mut _);
            sys::Esys_Free(name as *mut _);
            sys::Esys_Free(qualified_name as *mut _);
            let public = public?;
            Ok(Key {
                handle,
                public,
                name: name_bytes,
            })
        }
    }

    /// TPM2_PCR_Read.
    pub fn pcr_read(&mut self, selections: &[PcrSelection]) -> Result<PcrReadResult> {
        let sel_in = pcr_selection_list(selections);
        unsafe {
            let mut counter: u32 = 0;
            let mut sel_out: *mut sys::TPML_PCR_SELECTION = std::ptr::null_mut();
            let mut digests: *mut sys::TPML_DIGEST = std::ptr::null_mut();
            let rc = sys::Esys_PCR_Read(
                self.esys,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &sel_in,
                &mut counter,
                &mut sel_out,
                &mut digests,
            );
            check(rc, "Esys_PCR_Read")?;
            let count = (*digests).count as usize;
            let base = (*digests).digests.as_ptr();
            let values = (0..count.min(64))
                .map(|i| {
                    let d = &*base.add(i);
                    let bytes = std::slice::from_raw_parts(d.buffer.as_ptr(), d.size as usize);
                    PcrValue {
                        digest: bytes.to_vec(),
                    }
                })
                .collect();
            let selection = if (*sel_out).count > 0 {
                let s = &(*sel_out).pcrSelections[0];
                let n = (s.sizeofSelect as usize).min(3);
                let mut pcr_select = [0u8; 3];
                pcr_select[..n].copy_from_slice(&s.pcrSelect[..n]);
                Some(PcrSelection {
                    hash: s.hash,
                    pcr_select,
                })
            } else {
                None
            };
            sys::Esys_Free(sel_out as *mut _);
            sys::Esys_Free(digests as *mut _);
            Ok(PcrReadResult {
                update_counter: counter,
                values,
                selection,
            })
        }
    }

    /// TPM2_Quote: produce an attestation over the selected PCRs.
    pub fn quote(
        &mut self,
        key: &Key,
        qualifying_data: &[u8],
        selections: &[PcrSelection],
    ) -> Result<Quote> {
        let mut nonce = sys::TPM2B_DATA {
            size: qualifying_data.len().min(64) as u16,
            buffer: [0u8; 64],
        };
        nonce.buffer[..nonce.size as usize]
            .copy_from_slice(&qualifying_data[..nonce.size as usize]);
        let sel_in = pcr_selection_list(selections);
        let scheme = ecdsa_sha256_scheme();
        unsafe {
            let session = self.start_nullauth_session()?;
            let mut quoted: *mut sys::TPM2B_ATTEST = std::ptr::null_mut();
            let mut signature: *mut sys::TPMT_SIGNATURE = std::ptr::null_mut();
            let rc = sys::Esys_Quote(
                self.esys,
                key.handle,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &nonce,
                &scheme,
                &sel_in,
                &mut quoted,
                &mut signature,
            );
            if rc != 0 {
                self.flush_session(session);
                return Err(Error::Other(format!(
                    "Esys_Quote: tss2 RC 0x{rc:08x}"
                )));
            }
            let att_size = (*quoted).size as usize;
            let q = &*quoted;
            let attestation = q.attestationData[..att_size].to_vec();
            // `attestationData` holds raw wire bytes (clockInfo marshals as
            // 17 bytes), so parse the attested union by wire offsets rather
            // than casting to the padded C struct.
            let quote_info = crate::commands_key::parse_attestation_quote(&attestation)?;
            let pcr_select = quote_info.pcr_select;
            let pcr_digest = quote_info.pcr_digest;
            let (sig_h, sig_t) = parse_ecc_signature(&*signature)?;
            sys::Esys_Free(quoted as *mut _);
            sys::Esys_Free(signature as *mut _);
            self.flush_session(session);
            Ok(Quote {
                attestation,
                sig_h,
                sig_t,
                pcr_select,
                pcr_digest,
            })
        }
    }

    /// TPM2_Hash: compute a digest on the TPM and receive the hashcheck
    /// ticket for it. The dialect firmware requires this TPM-issued ticket
    /// for pre-hashed TPM2_Sign; a caller-computed (or empty) ticket is
    /// rejected as "invalid ticket" (0x3E0).
    pub fn hash(&mut self, data: &[u8], alg: u16) -> Result<(Vec<u8>, sys::TPMT_TK_HASHCHECK)> {
        let mut buf: sys::TPM2B_MAX_BUFFER = unsafe { mem::zeroed() };
        let len = data.len().min(1024);
        buf.buffer[..len].copy_from_slice(&data[..len]);
        buf.size = len as u16;
        let hierarchy = if self.dialect {
            sys::ESYS_TR_RH_OWNER
        } else {
            sys::ESYS_TR_RH_NULL
        };
        unsafe {
            let mut out_hash: *mut sys::TPM2B_DIGEST = std::ptr::null_mut();
            let mut validation: *mut sys::TPMT_TK_HASHCHECK = std::ptr::null_mut();
            let rc = sys::Esys_Hash(
                self.esys,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &buf,
                alg,
                hierarchy,
                &mut out_hash,
                &mut validation,
            );
            check(rc, "Esys_Hash")?;
            let h = &*out_hash;
            let digest = h.buffer[..h.size as usize].to_vec();
            let ticket = *validation;
            sys::Esys_Free(out_hash as *mut _);
            sys::Esys_Free(validation as *mut _);
            Ok((digest, ticket))
        }
    }

    /// TPM2_Sign: sign a pre-computed digest with an ECDSA key. `ticket`
    /// is the hashcheck ticket from `hash()` (required by the dialect
    /// firmware); `None` falls back to a caller-computed empty ticket,
    /// which only standard firmwares accept. Returns the (r, s) signature
    /// components.
    pub fn sign(
        &mut self,
        key: &Key,
        digest: &[u8],
        ticket: Option<&sys::TPMT_TK_HASHCHECK>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut d = sys::TPM2B_DIGEST {
            size: digest.len().min(64) as u16,
            buffer: [0u8; 64],
        };
        d.buffer[..d.size as usize].copy_from_slice(&digest[..d.size as usize]);
        let ticket_val = match ticket {
            Some(t) => *t,
            None => {
                let ticket_hierarchy = if self.dialect {
                    rh_dialect::OWNER
                } else {
                    0x0000_0000u32
                };
                let mut t: sys::TPMT_TK_HASHCHECK = sys::TPMT_TK_HASHCHECK {
                    tag: 0x0080_24,
                    hierarchy: ticket_hierarchy,
                    digest: unsafe { mem::zeroed() },
                };
                if self.dialect {
                    t.digest.size = 64;
                }
                t
            }
        };
        let scheme = ecdsa_sha256_scheme();
        unsafe {
            let session = self.start_nullauth_session()?;
            let mut signature: *mut sys::TPMT_SIGNATURE = std::ptr::null_mut();
            let rc = sys::Esys_Sign(
                self.esys,
                key.handle,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &d,
                &scheme,
                &ticket_val,
                &mut signature,
            );
            if rc != 0 {
                self.flush_session(session);
                return Err(Error::Other(format!("Esys_Sign: tss2 RC 0x{rc:08x}")));
            }
            let (r, s) = parse_ecc_signature(&*signature)?;
            sys::Esys_Free(signature as *mut _);
            self.flush_session(session);
            Ok((r, s))
        }
    }

    /// Start an unbound policy session (dialect `TPM2_SE_POLICY`). The
    /// session is flushed by the caller (or on drop of the context).
    pub fn start_policy_session(&mut self) -> Result<u32> {
        self.start_auth_session(TPM_SE_POLICY_DIALECT)
    }

    /// Start an unbound auth session of an explicit `TPM2_SE` type
    /// (bisect helper: the staged dialect header claims POLICY=0x01, but the
    /// firmware's accepted values may follow the standard enum where
    /// POLICY=0x02).
    pub fn start_auth_session(&mut self, session_type: u8) -> Result<u32> {
        let nonce_bytes = self.get_random(32)?;
        let mut nonce: sys::TPM2B_NONCE = unsafe { mem::zeroed() };
        nonce.size = nonce_bytes.len() as u16;
        nonce.buffer[..nonce.size as usize].copy_from_slice(&nonce_bytes);
        unsafe {
            let mut session: u32 = 0;
            let sym: sys::TPMT_SYM_DEF = sys::TPMT_SYM_DEF {
                algorithm: TPM_ALG_NULL,
                keyBits: mem::zeroed(),
                mode: mem::zeroed(),
            };
            let rc = sys::Esys_StartAuthSession(
                self.esys,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_RH_NULL,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &nonce,
                session_type,
                &sym,
                TPM_ALG_SHA256,
                &mut session,
            );
            check(rc, "Esys_StartAuthSession")?;
            Ok(session)
        }
    }

    /// TPM2_PolicyRestart: reset the session's policy digest to empty.
    pub fn policy_restart(&mut self, session: u32) -> Result<()> {
        let rc = unsafe {
            sys::Esys_PolicyRestart(self.esys, session, sys::ESYS_TR_NONE, sys::ESYS_TR_NONE, sys::ESYS_TR_NONE)
        };
        check(rc, "Esys_PolicyRestart")
    }

    /// TPM2_PolicyPCR: extend the session policy with the given selection.
    /// `pcr_digest` is the expected digest of the selected PCRs; `None`
    /// means zero-length, i.e. the TPM reads the current PCR values.
    pub fn policy_pcr(
        &mut self,
        session: u32,
        pcr_digest: Option<&[u8]>,
        selections: &[PcrSelection],
    ) -> Result<()> {
        let sel = pcr_selection_list(selections);
        // Owned digest (if any); its pointer is handed to the FFI call below.
        let digest: Option<sys::TPM2B_DIGEST> = match pcr_digest {
            Some(d) => {
                if d.len() > 64 {
                    return Err(Error::Malformed("pcr digest exceeds 64 bytes".into()));
                }
                let mut dig: sys::TPM2B_DIGEST = unsafe { mem::zeroed() };
                dig.size = d.len() as u16;
                dig.buffer[..d.len()].copy_from_slice(d);
                Some(dig)
            }
            None => None,
        };
        let digest_ptr: *const sys::TPM2B_DIGEST = match digest.as_ref() {
            Some(d) => d as *const _,
            None => std::ptr::null(),
        };
        let rc = unsafe {
            sys::Esys_PolicyPCR(
                self.esys,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                digest_ptr,
                &sel,
            )
        };
        check(rc, "Esys_PolicyPCR")
    }

    /// TPM2_PolicyGetDigest: the session's current policy digest.
    pub fn policy_get_digest(&mut self, session: u32) -> Result<Vec<u8>> {
        unsafe {
            let mut out: *mut sys::TPM2B_DIGEST = std::ptr::null_mut();
            let rc = sys::Esys_PolicyGetDigest(
                self.esys,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &mut out,
            );
            check(rc, "Esys_PolicyGetDigest")?;
            let d = &*out;
            let bytes = d.buffer[..d.size as usize].to_vec();
            sys::Esys_Free(out as *mut _);
            Ok(bytes)
        }
    }

    /// TPM2_Create: seal `data` under the parent (a loaded storage key) as
    /// a `TPM_ALG_KEYEDHASH` data object (NULL scheme). `policy_digest` is the
    /// bound `authPolicy` (empty for auth-only objects). The TPM returns the
    /// wrapped `private` blob; the object is not loaded yet.
    pub fn create_data_object(
        &mut self,
        parent: u32,
        data: &[u8],
        policy_digest: &[u8],
    ) -> Result<DataObject> {
        // A data object (seal/unseal) uses the NULL keyedHash scheme. The
        // firmware rejects XOR and HMAC keyedHash (0x2D2 "unsupported or
        // incompatible scheme") — bisected on a live SEV-SNP NitroTPM: only
        // the NULL scheme is accepted. XOR/HMAC are keyedHash *operations*
        // (key derivation / MAC), not sealing.
        self.create_data_object_with_scheme(parent, data, policy_digest, TPM_ALG_NULL, 0)
    }

    /// `create_data_object` with an explicit keyedHash scheme (bisect helper):
    /// `scheme` = XOR(0x0A) / HMAC(0x05) / NULL(0x10); `kdf` only for XOR.
    pub fn create_data_object_with_scheme(
        &mut self,
        parent: u32,
        data: &[u8],
        policy_digest: &[u8],
        scheme: u16,
        kdf: u16,
    ) -> Result<DataObject> {
        if data.len() > 256 {
            return Err(Error::Malformed("data exceeds 256-byte sensitive data".into()));
        }
        let parent_tr = hierarchy_to_esys_tr(parent);
        let in_sensitive = {
            let mut s: sys::TPM2B_SENSITIVE_CREATE = unsafe { mem::zeroed() };
            s.sensitive.data.size = data.len() as u16;
            s.sensitive.data.buffer[..data.len()].copy_from_slice(data);
            s.size = marshal_sensitive_create(&s.sensitive)?
                .len() as u16;
            s
        };
        let in_public = {
            let area = build_keyedhash_public(scheme, kdf, policy_digest);
            let mut pub2b = sys::TPM2B_PUBLIC {
                size: 0,
                publicArea: area,
            };
            pub2b.size = marshal_public(&area)?.len() as u16;
            pub2b
        };
        unsafe {
            let outside_info: sys::TPM2B_DATA = mem::zeroed();
            let creation_pcr: sys::TPML_PCR_SELECTION = mem::zeroed();
            let session = self.start_nullauth_session()?;
            let mut out_private: *mut sys::TPM2B_PRIVATE = std::ptr::null_mut();
            let mut out_public: *mut sys::TPM2B_PUBLIC = std::ptr::null_mut();
            let mut creation_data: *mut sys::TPM2B_CREATION_DATA = std::ptr::null_mut();
            let mut creation_hash: *mut sys::TPM2B_DIGEST = std::ptr::null_mut();
            let mut creation_ticket: *mut sys::TPMT_TK_CREATION = std::ptr::null_mut();
            let rc = sys::Esys_Create(
                self.esys,
                parent_tr,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &in_sensitive,
                &in_public,
                &outside_info,
                &creation_pcr,
                &mut out_private,
                &mut out_public,
                &mut creation_data,
                &mut creation_hash,
                &mut creation_ticket,
            );
            self.flush_session(session);
            if rc != 0 {
                return Err(Error::Other(format!(
                    "Esys_Create (parent 0x{parent:08x}, scheme 0x{scheme:04x}): \
                     tss2 RC 0x{rc:08x} ({})",
                    decode_rc(rc)
                )));
            }
            let priv_buf = {
                let p = &*out_private;
                let b = p.buffer[..p.size as usize].to_vec();
                sys::Esys_Free(out_private as *mut _);
                b
            };
            let pub_area = (*out_public).publicArea;
            sys::Esys_Free(out_public as *mut _);
            sys::Esys_Free(creation_data as *mut _);
            sys::Esys_Free(creation_hash as *mut _);
            sys::Esys_Free(creation_ticket as *mut _);
            let public = marshal_public(&pub_area)?;
            // Name = nameAlg (2B BE) || H(marshaled TPMT_PUBLIC), per Part 1 16.9.
            let name = {
                let mut n = Vec::with_capacity(2 + 32);
                n.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                n.extend_from_slice(&Sha256::digest(&public));
                n
            };
            Ok(DataObject {
                handle: 0,
                private: priv_buf,
                public,
                name,
            })
        }
    }

    /// TPM2_Load: load a previously created data object under `parent`.
    /// Cross-checks the TPM-computed Name against the stored one.
    pub fn load_data_object(&mut self, parent: u32, data: &DataObject) -> Result<DataObject> {
        let parent_tr = hierarchy_to_esys_tr(parent);
        let in_private = {
            let mut p: sys::TPM2B_PRIVATE = unsafe { mem::zeroed() };
            if data.private.len() > p.buffer.len() {
                return Err(Error::Malformed("private exceeds TPM2B_PRIVATE".into()));
            }
            p.size = data.private.len() as u16;
            p.buffer[..p.size as usize].copy_from_slice(&data.private);
            p
        };
        let in_public = {
            let mut area: sys::TPMT_PUBLIC = unsafe { mem::zeroed() };
            let mut off: u64 = 0;
            let rc = unsafe {
                sys::Tss2_MU_TPMT_PUBLIC_Unmarshal(
                    data.public.as_ptr(),
                    data.public.len() as u64,
                    &mut off,
                    &mut area,
                )
            };
            check(rc, "Tss2_MU_TPMT_PUBLIC_Unmarshal")?;
            let mut pub2b = sys::TPM2B_PUBLIC {
                size: 0,
                publicArea: area,
            };
            pub2b.size = marshal_public(&area)?.len() as u16;
            pub2b
        };
        unsafe {
            let session = self.start_nullauth_session()?;
            let mut handle: u32 = 0;
            let rc = sys::Esys_Load(
                self.esys,
                parent_tr,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &in_private,
                &in_public,
                &mut handle,
            );
            self.flush_session(session);
            check(rc, "Esys_Load")?;
            let mut name_ptr: *mut sys::TPM2B_NAME = std::ptr::null_mut();
            let rc = sys::Esys_TR_GetName(self.esys, handle, &mut name_ptr);
            check(rc, "Esys_TR_GetName")?;
            let n = &*name_ptr;
            let live_name = n.name[..n.size as usize].to_vec();
            sys::Esys_Free(name_ptr as *mut _);
            if live_name != data.name {
                return Err(Error::Malformed(format!(
                    "loaded object Name mismatch: stored {} live {}",
                    data.name.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    live_name.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                )));
            }
            Ok(DataObject {
                handle,
                ..data.clone()
            })
        }
    }

    /// TPM2_Unseal: recover the sealed data of a loaded data object,
    /// authorized by the caller's (null-auth) session.
    pub fn unseal(&mut self, item: u32) -> Result<Vec<u8>> {
        unsafe {
            let session = self.start_nullauth_session()?;
            let mut out: *mut sys::TPM2B_SENSITIVE_DATA = std::ptr::null_mut();
            let rc = sys::Esys_Unseal(self.esys, item, session, sys::ESYS_TR_NONE, sys::ESYS_TR_NONE, &mut out);
            self.flush_session(session);
            check(rc, "Esys_Unseal")?;
            let d = &*out;
            let bytes = d.buffer[..d.size as usize].to_vec();
            sys::Esys_Free(out as *mut _);
            Ok(bytes)
        }
    }

    /// TPM2_Unseal authorized by a live policy session (the object must carry
    /// a matching `authPolicy`). `session` is flushed on the way out.
    pub fn unseal_policy(&mut self, item: u32, session: u32) -> Result<Vec<u8>> {
        unsafe {
            let mut out: *mut sys::TPM2B_SENSITIVE_DATA = std::ptr::null_mut();
            let rc = sys::Esys_Unseal(self.esys, item, session, sys::ESYS_TR_NONE, sys::ESYS_TR_NONE, &mut out);
            self.flush_session(session);
            check(rc, "Esys_Unseal(policy)")?;
            let d = &*out;
            let bytes = d.buffer[..d.size as usize].to_vec();
            sys::Esys_Free(out as *mut _);
            Ok(bytes)
        }
    }

    /// Register an existing TPM handle (e.g. a persistent 0x81xx_xxxx) as an
    /// ESYS_TR resource object. This is the ESAPI equivalent of the
    /// tpm2-tools flow: the ESAPI wrappers only operate on persistent handles
    /// through a registered resource (a raw persistent u32 passed straight to
    /// them fails "Esys handle does not exist", 0x00070018). The returned
    /// ESYS_TR is released by `Esys_Finalize` on context drop (this binding
    /// exposes no per-resource delete; `Esys_TR_Close` takes `*mut ESYS_TR`
    /// and is not used).
    pub fn from_tpm_public(&mut self, tpm_handle: u32) -> Result<u32> {
        unsafe {
            let mut esys_tr: u32 = 0;
            let rc = sys::Esys_TR_FromTPMPublic(
                self.esys,
                tpm_handle,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &mut esys_tr,
            );
            check(rc, "Esys_TR_FromTPMPublic")?;
            Ok(esys_tr)
        }
    }

    /// TPM2_EvictControl: move `object` (a loaded transient, or a persistent
    /// handle registered via `from_tpm_public`) to the `persistent` handle
    /// (0x81xx_xxxx), or — with `persistent` = 0 — unload the object at
    /// `object`. `auth` is the authorizing hierarchy (OWNER for an empty-auth
    /// data object). The `tpm2_evictcontrol` model: the object survives
    /// reboots and is reachable by tpm2-tools under the same handle.
    pub fn evict_control(&mut self, auth: u32, object: u32, persistent: u32) -> Result<()> {
        let auth_tr = hierarchy_to_esys_tr(auth);
        unsafe {
            let session = self.start_nullauth_session()?;
            let mut new_handle: u32 = 0;
            let rc = sys::Esys_EvictControl(
                self.esys,
                auth_tr,
                object,
                session,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                persistent,
                &mut new_handle,
            );
            self.flush_session(session);
            check(rc, "Esys_EvictControl")
        }
    }
}

fn parse_ecc_signature(sig: &sys::TPMT_SIGNATURE) -> Result<(Vec<u8>, Vec<u8>)> {
    if sig.sigAlg != TPM_ALG_ECDSA {
        return Err(Error::Malformed(format!(
            "unexpected signature scheme 0x{0:04x}",
            sig.sigAlg
        )));
    }
    let esig = unsafe { &sig.signature.ecdsa };
    Ok((
        esig.signatureR.buffer[..esig.signatureR.size as usize].to_vec(),
        esig.signatureS.buffer[..esig.signatureS.size as usize].to_vec(),
    ))
}

impl Drop for EsysTpm {
    fn drop(&mut self) {
        unsafe {
            let _ = sys::Esys_Finalize(&mut self.esys);
        }
        Self::finalize_device_tcti(&mut self.tcti);
    }
}

unsafe impl Send for EsysTpm {}
