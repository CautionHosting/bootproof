use thiserror::Error;

/// Errors from the raw TPM2 client.
#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TPM returned response code 0x{0:04X} ({1})")]
    Tpm(u16, String),

    #[error("malformed TPM response: {0}")]
    Malformed(String),

    #[error("device not started (send TPM2_Startup)")]
    NeedsStartup,

    #[error("no response from TPM device")]
    Eof,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Best-effort human-readable name for a TPM return code.
pub fn rc_name(code: u16) -> String {
    use crate::constants::rc::*;
    let name = match code {
        SUCCESS => "SUCCESS",
        FAILURE => "FAILURE",
        INITIALIZE => "INITIALIZE (needs Startup)",
        VALUE => "VALUE",
        NO_RESULT => "NO_RESULT",
        SIZE => "SIZE",
        TAG => "TAG",
        INSUFFICIENT => "INSUFFICIENT",
        COMMAND_SIZE => "COMMAND_SIZE",
        COMMAND_CODE => "COMMAND_CODE",
        INVALID_HANDLE => "INVALID_HANDLE",
        AUTH_FAIL => "AUTH_FAIL",
        BAD_AUTH => "BAD_AUTH",
        RETRY => "RETRY",
        _ => return format!("UNKNOWN(0x{code:04X})"),
    };
    format!("{name} (0x{code:04X})")
}
