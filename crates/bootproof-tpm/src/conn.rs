//! Raw TPM2 connection: command framing and transfer over a pluggable backend.
//!
//! A TPM 2.0 command/response is a byte buffer with a 10-byte header followed
//! by handles + parameters:
//!
//! ```text
//! tag    u16   TPM_ST_NO_SESSIONS (0x8001) or TPM_ST_SESSIONS (0x8002)
//! size   u32   total command/response size, including this header
//! code   u32   TPM_CC for commands, TPM_RC for responses
//! body   ...   command handles and parameters
//! ```
//!
//! All fields are big-endian. This is the on-the-wire format used by the
//! kernel char device (`/dev/tpm0`), the TSS2 stack, and the TPM 2.0
//! reference model (swtpm/libtpms). Body structures follow the TCG spec:
//! `TPML_*` arrays carry a `u32` count, and `TPMS_PCR_SELECTION` is
//! `{hash u16, pcrSelectSize u8, pcrSelect[pcrSelectSize]}`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use crate::constants::rc;
use crate::error::{Error, Result};

/// Size of the TPM2 command/response header in bytes.
pub const HEADER_SIZE: usize = 10;

/// Where commands go.
///
/// The char device is a persistent handle: every command travels over the
/// single opened file. The swtpm TCP/Unix backends keep one persistent
/// connection: TPM2 sessions (policy sessions, loaded primary keys) are
/// keyed to the connection, so a per-command connection would drop them.
enum Backend {
    Device(std::fs::File),
    SwtpmTcp(SocketAddr, Option<TcpStream>),
    SwtpmUnix(PathBuf, Option<UnixStream>),
}

/// A minimal command builder.
#[derive(Debug)]
pub struct Command {
    pub tag: u16,
    pub code: u16,
    pub body: Vec<u8>,
}

impl Command {
    pub fn new(code: u16, tag: u16) -> Self {
        Self {
            tag,
            code,
            body: Vec::new(),
        }
    }

    pub fn push_u8(&mut self, v: u8) {
        self.body.push(v);
    }
    pub fn push_u16(&mut self, v: u16) {
        self.body.extend_from_slice(&v.to_be_bytes());
    }
    pub fn push_u32(&mut self, v: u32) {
        self.body.extend_from_slice(&v.to_be_bytes());
    }
    pub fn push_bytes(&mut self, v: &[u8]) {
        self.body.extend_from_slice(v);
    }

    /// Serialize to the wire format (10-byte header + body).
    pub fn encode(&self) -> Vec<u8> {
        let size = (HEADER_SIZE + self.body.len()) as u32;
        let mut buf = Vec::with_capacity(size as usize);
        buf.extend_from_slice(&self.tag.to_be_bytes());
        buf.extend_from_slice(&size.to_be_bytes());
        buf.extend_from_slice(&(self.code as u32).to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }
}

/// Read the total buffer size out of a response buffer that already contains
/// the full header.
fn response_size(resp: &[u8]) -> u32 {
    u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]])
}

/// Write one command and read the complete response that follows it.
fn read_response<W: Read + Write>(conn: &mut W, cmd: &[u8]) -> Result<Vec<u8>> {
    conn.write_all(cmd)?;

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = conn.read(&mut tmp)?;
        if n == 0 {
            if buf.len() < HEADER_SIZE {
                return Err(Error::Eof);
            }
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() >= HEADER_SIZE {
            let size = response_size(&buf) as usize;
            if buf.len() >= size {
                buf.truncate(size);
                break;
            }
        }
    }
    Ok(buf)
}

/// Parse a complete response buffer into `(response_code, body)`.
pub(crate) fn parse_response(resp: &[u8]) -> Result<(u32, Vec<u8>)> {
    if resp.len() < HEADER_SIZE {
        return Err(Error::Malformed(format!(
            "response too short: {} bytes",
            resp.len()
        )));
    }
    let code = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    Ok((code, resp[HEADER_SIZE..].to_vec()))
}

/// Send `CMD_INIT` over a swtpm **control** channel to bring the emulated
/// TPM up. swtpm (libtpms) will not process any command on the data channel
/// until `TPMInit` has run, which this control command triggers.
///
/// Control-channel protocol (swtpm `tpm_ioctl.h`): each message is a
/// `{ u32 ordinal (BE), body }`. `CMD_INIT = 2`; its request body is
/// `ptm_init.u.req.init_flags` (a `u32`, 0 = keep volatile state) and its
/// response is a `u32` TPM result (0 = success). The control connection can
/// be closed afterwards; the data channel is independent.
pub fn swtpm_ctrl_init(ctrl_path: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(ctrl_path).map_err(Error::from)?;
    let mut msg = Vec::new();
    msg.extend_from_slice(&2u32.to_be_bytes()); // CMD_INIT
    msg.extend_from_slice(&0u32.to_be_bytes()); // init_flags = 0
    stream.write_all(&msg)?;
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp)?;
    let result = u32::from_be_bytes(resp);
    if result != 0 {
        return Err(Error::Other(format!(
            "swtpm control INIT failed: 0x{:04x}",
            result
        )));
    }
    Ok(())
}

/// A raw TPM2 connection.
pub struct Tpm {
    backend: Backend,
    /// True when the TPM speaks the libtpms-derived wire profile. Both
    /// targets (the firmware TPM and the in-tree swtpm) are built from
    /// libtpms 0.10.2, which is a fixed, byte-for-byte verifiable format —
    /// not a runtime-detected "dialect". The profile is therefore set
    /// explicitly by each connector (always `true`) rather than probed.
    ///
    /// The profile diverges from the TCG spec text in a few places that are
    /// pinned by the libtpms source and confirmed on the wire:
    ///   * `TPMA_SESSION` is a single byte (spec: 4).
    ///   * `TPM_SE` numbering is HMAC=0x00, POLICY=0x01, TRIAL=0x03 (the spec
    ///     inserts PASSWORD=0x00, shifting the rest).
    ///   * `TPMS_SENSITIVE_CREATE` has no `sensitiveType` field.
    ///   * `TPML_DIGEST_VALUES` / `TPMT_HA` entries are `hashAlg u16` + RAW
    ///     digest (no `TPM2B` size prefix) in command parameters.
    pub dialect: bool,
}

impl Tpm {
    /// Open a TPM kernel character device (`/dev/tpm0` or `/dev/tpmrm0`).
    pub fn open(path: &Path) -> Result<Self> {
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Ok(Self {
            backend: Backend::Device(fd),
            // The firmware TPM is libtpms-derived; set the profile explicitly.
            dialect: true,
        })
    }

    /// Connect to a swtpm over TCP (`swtpm socket --server type=tcp,port=N`).
    /// A fresh connection is made per command.
    pub fn connect_swtpm_tcp(addr: &str) -> Result<Self> {
        let a: SocketAddr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| Error::Other(e.to_string()))?;
        Ok(Self {
            backend: Backend::SwtpmTcp(a, None),
            dialect: true,
        })
    }

    /// Connect to a swtpm over a Unix socket (`swtpm socket --server type=unix`).
    pub fn connect_swtpm_unix(path: &Path) -> Result<Self> {
        Ok(Self {
            backend: Backend::SwtpmUnix(path.to_path_buf(), None),
            dialect: true,
        })
    }

    /// Send a command and return the full response buffer.
    ///
    /// The device backend reuses the single opened file for every command.
    /// Dup'ing the fd per command must be avoided: the NitroTPM driver keys
    /// per-connection session state to the open, and a dup'd descriptor ends
    /// up in the policy-session handle pool (0x03xxxxxx) instead of the
    /// regular pool (0x02xxxxxx).
    pub fn transfer(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        match &mut self.backend {
            Backend::Device(f) => read_response(f, cmd),
            Backend::SwtpmTcp(addr, conn) => {
                if conn.is_none() {
                    *conn = Some(TcpStream::connect(*addr).map_err(Error::from)?);
                }
                read_response(conn.as_mut().unwrap(), cmd)
            }
            Backend::SwtpmUnix(path, conn) => {
                if conn.is_none() {
                    *conn = Some(UnixStream::connect(path).map_err(Error::from)?);
                }
                read_response(conn.as_mut().unwrap(), cmd)
            }
        }
    }

    /// Send a command and return the response body (after the header),
    /// checking the response code.
    pub fn call(&mut self, cmd: &Command) -> Result<(u32, Vec<u8>)> {
        let resp = self.transfer(&cmd.encode())?;
        let (code, body) = parse_response(&resp)?;
        if code != rc::SUCCESS as u32 {
            if code == rc::INITIALIZE as u32 {
                return Err(Error::NeedsStartup);
            }
            return Err(Error::Tpm(code as u16, crate::error::rc_name(code as u16)));
        }
        Ok((code, body))
    }
}
