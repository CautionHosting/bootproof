//! bootproof-tpm: a minimal raw TPM 2.0 client.
//!
//! Talks to a TPM (kernel char device, or a swtpm over TCP/Unix) with
//! hand-rolled command framing. No tss2, no libtpms -- just the protocol.
//! This is the foundation for the `tpm2` attestation channel.
//!
//! The wire format is the standard TCG TPM 2.0 command stream: a 10-byte
//! header `{tag u16, size u32, code u32}` (big-endian) followed by handles +
//! parameters. This is the same format the kernel char device (`/dev/tpm0`),
//! the TSS2 stack, and the reference model (swtpm/libtpms) all use.
//!
//! All multi-byte fields are big-endian.

pub mod commands;
pub mod commands_key;
pub mod commands_policy;
pub mod conn;
pub mod constants;
pub mod error;
#[cfg(feature = "attest")]
pub mod attest;
#[cfg(feature = "esys")]
pub mod esys;
pub mod session;

pub use commands::{PcrReadResult, PcrSelection, PcrValue};
pub use commands_key::{Key, Quote};
pub use commands_policy::{policy_pcr_auth_policy, parse_public_area, PublicArea};
pub use conn::{Command, Tpm};
pub use error::{Error, Result};
#[cfg(feature = "esys")]
pub use esys::EsysTpm;
pub use session::Session;

impl Tpm {
    /// Ensure the TPM is started (send `TPM2_Startup` if it reports it needs
    /// to). Works for any transport.
    pub fn ensure_started(&mut self) -> Result<()> {
        match self.pcr_read(&[PcrSelection::all(constants::alg::SHA256)]) {
            Ok(_) => Ok(()),
            Err(Error::NeedsStartup) => {
                // Prefer TPM_SU_STATE (preserves PCRs); fall back to CLEAR.
                if let Err(_) = self.startup(true) {
                    self.startup(false)?;
                }
                self.pcr_read(&[PcrSelection::all(constants::alg::SHA256)])?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Open a TPM kernel char device and ensure it is started.
    pub fn open_started(path: &std::path::Path) -> Result<Self> {
        let mut tpm = Self::open(path)?;
        tpm.detect_dialect();
        tpm.ensure_started()?;
        Ok(tpm)
    }

    /// Connect to swtpm over TCP and ensure started.
    pub fn connect_swtpm_tcp_started(addr: &str) -> Result<Self> {
        let mut tpm = Self::connect_swtpm_tcp(addr)?;
        tpm.detect_dialect();
        tpm.ensure_started()?;
        Ok(tpm)
    }

    /// Connect to swtpm over a Unix socket and ensure started.
    pub fn connect_swtpm_unix_started(path: &std::path::Path) -> Result<Self> {
        let mut tpm = Self::connect_swtpm_unix(path)?;
        tpm.detect_dialect();
        tpm.ensure_started()?;
        Ok(tpm)
    }
}
