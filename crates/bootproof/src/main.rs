//! `bootproof` — unified remote-attestation binary.
//!
//! Subcommands:
//!   attest   — node server: serve a REST remote-attestation API
//!   verify   — client: challenge a node, verify proof offline, print facts
//!   decrypt  — decrypt a blob with the local (PCR-gated) TPM key
//!   sign     — sign data with the local (PCR-gated) TPM key
//!   tpm-probe— debug: read PCRs + properties from a local TPM
//!   nsi      — request the NitroTPM attestation document bound to a nonce

mod tpm_probe;
mod verify_nitro;

use std::path::PathBuf;

use base64::Engine as _;
use clap::{Parser, Subcommand};

use bootproof_tpm::Tpm;
#[derive(Parser)]
#[command(name = "bootproof", version, about = "Unified remote attestation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Talk to a local TPM and print PCRs + properties (debug).
    TpmProbe {
        /// TPM kernel character device (default /dev/tpm0).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// Connect to swtpm over TCP (host:port). Overrides --device.
        #[arg(long)]
        tcp: Option<String>,
        /// Connect to swtpm over a Unix socket (socket path).
        #[arg(long)]
        unix: Option<PathBuf>,
        /// Comma-separated list of PCR indices to read (default: 0-23).
        #[arg(long)]
        pcrs: Option<String>,
        /// Send a raw TPM2 command (hex bytes) and print the response.
        #[arg(long)]
        raw: Option<String>,
        /// Run the session-based ECC P-256 CreatePrimary and report the RC.
        #[arg(long)]
        create_key: bool,
        /// Run a session-based RSA2048 EK CreatePrimary in the Endorsement
        /// hierarchy (the AWS nitro-tpm-attest flow) and report the RC.
        #[arg(long)]
        create_ek: bool,
    },
    /// Serve a REST remote-attestation API for this node.
    Attest {
        /// Address to listen on (default :443).
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: String,
        /// State directory for the TLS key + TPM keys (default /var/lib/bootproof).
        #[arg(long, default_value = "/var/lib/bootproof")]
        state: PathBuf,
        /// Static TLS key (PEM). If absent, one is generated and persisted.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Optional metadata JSON file.
        #[arg(long)]
        metadata: Option<PathBuf>,
        /// Connect to swtpm over TCP (host:port). Overrides char-device detection.
        #[arg(long)]
        tcp: Option<String>,
    },
    /// Run the collect daemon: the SOLE process that touches the
    /// attestation hardware (/dev/tpm0, /dev/sev-guest). Listens on a Unix
    /// domain socket and collects signed evidence for one 64-byte challenge
    /// per connection. The sandboxed `attest` node talks to this daemon
    /// instead of reading devices directly (gVisor forbids the device reads).
    Collect {
        /// Unix domain socket to listen on (default /run/bootproof/collect.sock).
        #[arg(long, default_value = "/run/bootproof/collect.sock")]
        socket: PathBuf,
        /// Connect to swtpm over TCP (host:port). Overrides char-device detection.
        #[arg(long)]
        tcp: Option<String>,
    },
    /// Verify and print the trust tree (no target), or challenge a remote
    /// node (with target), verify its proof offline, and print the facts table.
    Verify {
        /// Remote target: host, host:port, IP, or domain (resolves via
        /// _bootproof TXT). Omit to render the local trust tree of this system.
        target: Option<String>,
        /// Override the endpoint port (remote only).
        #[arg(long)]
        port: Option<u16>,
        /// Use the given endpoint directly, skipping DNS discovery (remote only).
        #[arg(long)]
        direct: bool,
        /// Trust the daemon's pubkey on first contact, TOFU (remote only).
        #[arg(long)]
        trust: bool,
        /// Persist the pin for this host (remote only).
        #[arg(long)]
        pin: bool,
        /// Dump the raw attestation bundle, base64 (remote only).
        #[arg(long)]
        bundle: bool,
        /// Directory of trust roots, overriding embedded roots (remote only).
        #[arg(long)]
        roots: Option<PathBuf>,
        /// Request timeout in seconds (remote only).
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// TPM kernel character device, default /dev/tpm0 (local tree).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// Connect via tpm-bridge TCP endpoint, host:port. Overrides --device.
        #[arg(long)]
        tcp: Option<String>,
        /// Raw NV index of the persistent NSM scratch buffer, hex u32.
        #[arg(long, default_value = "0")]
        nv_index: String,
        /// Emit JSON instead of the rendered tree / facts table.
        #[arg(long)]
        json: bool,
        /// Full evidence tree with all vendor detail (local tree only;
        /// default output is a succinct summary with per-fact vendor roots).
        #[arg(long)]
        expert: bool,
        /// Pinned expected-PCR policy file, JSON `{{"<idx>": "<hex|b64>"}}`
        /// (local tree only). The attested PCRs must match; establish a
        /// known-good baseline with `verify-nitro --emit-pcrs`.
        #[arg(long)]
        pcr_policy: Option<PathBuf>,
        /// Metadata to place in the NitroTPM attestation request (local
        /// tree only). The signer echoes it into the AWS-signed document,
        /// so it becomes metadata authenticated by the pinned AWS root and
        /// bound to the same signed PCRs/nonce (8 KiB request limit).
        #[arg(long)]
        user_data: Option<String>,
        /// Require at least this attestation level (0..=3); exit 4 if the
        /// derived level is below it (local tree only). Levels: 0 software
        /// TPM, 1 hardware TPM, 2 CVM dual attestation, 3 ring isolation.
        #[arg(long)]
        min_level: Option<u8>,
    },
    /// Decrypt a blob with the local TPM (gated by the attested PCR state).
    Decrypt {
        /// The encrypted blob (base64 or path to file).
        blob: String,
        /// State directory for the TPM keys (default /var/lib/bootproof).
        #[arg(long, default_value = "/var/lib/bootproof")]
        state: PathBuf,
    },
    /// Sign data with the local TPM (gated by the attested PCR state).
    Sign {
        /// The data to sign (raw bytes or path to file).
        data: String,
        /// State directory for the TPM keys (default /var/lib/bootproof).
        #[arg(long, default_value = "/var/lib/bootproof")]
        state: PathBuf,
    },
    /// Seal/unseal a LUKS volume key (TPM2 data object + optional SEV-SNP gate).
    Dmext {
        #[command(subcommand)]
        op: DmextOp,
    },
    /// Bridge a TCP port to the local TPM (raw TPM2 framing). For capturing
    /// commands from remote tooling (e.g. tss-esapi over an SSH tunnel).
    TpmBridge {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:51000")]
        listen: String,
        /// swtpm control-socket address (returns success for all control
        /// commands; needed by tss2's swtpm TCTI).
        #[arg(long)]
        control: Option<String>,
        /// TPM kernel character device (default /dev/tpm0).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// Append a hex log of every command/response to this file.
        #[arg(long)]
        log: Option<PathBuf>,
    },
    /// Request the NitroTPM attestation document (AWS NSM vendor command)
    /// bound to a nonce, and print it base64.
    Nsi {
        /// TPM kernel character device (default /dev/tpm0).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// The nonce to bind (hex or base64; default: 32 random bytes).
        #[arg(long)]
        nonce: Option<String>,
        /// Extra user data to echo (hex or base64).
        #[arg(long)]
        user_data: Option<String>,
        /// A client public key (PEM/DER file) to include in the document.
        #[arg(long)]
        public_key: Option<PathBuf>,
        /// Raw NV index of the persistent scratch buffer (hex u32).
        #[arg(long, default_value = "1")]
        nv_index: String,
        /// Connect via tpm-bridge TCP endpoint (host:port).
        #[arg(long)]
        tcp: Option<String>,
    },
    /// Serve a self-contained NitroTPM attestation API (plain HTTP):
    /// `POST /attest` returns the nonce-bound attestation chain.
    Serve {
        /// Address to listen on (default 127.0.0.1:8443).
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
        /// TPM kernel character device (default /dev/tpm0).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// Connect via tpm-bridge TCP endpoint (host:port). Overrides --device.
        #[arg(long)]
        tcp: Option<String>,
        /// Raw NV index of the persistent NSM scratch buffer (hex u32).
        #[arg(long, default_value = "0")]
        nv_index: String,
    },
    /// Verify a NitroTPM attestation against the AWS Nitro roots of trust
    /// (signature + chain + nonce, plus an optional pinned-PCR policy).
    VerifyNitro {
        /// The attestation: a `serve` JSON response, or a raw base64 COSE doc.
        doc: PathBuf,
        /// Expected nonce (hex or base64). Defaults to a serve JSON doc's nonce.
        #[arg(long)]
        nonce: Option<String>,
        /// JSON file of expected PCRs `{"0": "hex", ...}`. If absent, no PCR
        /// policy is checked (signature + chain + nonce only).
        #[arg(long)]
        pcrs: Option<PathBuf>,
        /// Verify at this Unix time (seconds) instead of the current wall clock.
        #[arg(long)]
        time: Option<u64>,
        /// After a successful verify, write the doc's PCRs here as a
        /// known-good reference.
        #[arg(long)]
        emit_pcrs: Option<PathBuf>,
        /// Emit JSON instead of the facts table.
        #[arg(long)]
        json: bool,
    },
    /// Probe NV_DefineSpace attribute layouts against a live TPM.
    NvTest {
        /// TPM kernel character device (default /dev/tpm0).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// NV index name algorithm (hex u16; default 0x0b SHA256).
        #[arg(long, default_value = "0b")]
        name_alg: String,
        /// TPMA_NV attribute bits (hex u32; default 0x40004 auth-read|auth-write).
        #[arg(long, default_value = "40004")]
        attrs: String,
        /// Data area size (bytes; default 8192).
        #[arg(long, default_value_t = 8192)]
        size: u16,
        /// NV auth value (hex; omit for NULL auth).
        #[arg(long)]
        auth: Option<String>,
        /// NV index handle (hex u32; default 0 = TPM-assigned).
        #[arg(long, default_value = "0")]
        index: String,
        /// Replicate the platform tpm2-tools exact command sequence.
        #[arg(long)]
        mimic: bool,
        /// Undefine the given raw NV indices (comma-separated hex).
        #[arg(long)]
        undefine: Option<String>,
        /// Try several NV_DefineSpace session/no-session forms.
        #[arg(long)]
        forms: bool,
        /// Sequence bisection for the define session failure.
        #[arg(long)]
        seq: bool,
        /// Undefine handle-base/entity matrix for a single raw index.
        #[arg(long)]
        umatrix: Option<String>,
        /// Send a raw hex command verbatim and print rc + response.
        #[arg(long)]
        raw: Option<String>,
        /// Connect via tpm-bridge TCP endpoint (host:port) instead of the
        /// char device.
        #[arg(long)]
        tcp: Option<String>,
        /// Replay platform-captured SAS + define hex (two space-separated
        /// hex strings).
        #[arg(long)]
        replay: Option<String>,
        /// NV read/write handle-pair probe for an existing raw index.
        #[arg(long)]
        rw: Option<String>,
        /// Comma-separated read/write sizes to bisection-test (applies to
        /// --rw; each size is used for both the NV_Read size and the
        /// NV_Write data size).
        #[arg(long, default_value = "4,8,15,16,17,32,57")]
        rw_sizes: String,
        /// Run TPM2_Clear against candidate lockout hierarchy handles to
        /// release DA lockout (0x0921).
        #[arg(long)]
        clear: bool,
    },
    /// Parse a StageX /provenance.spdx (SPDX 2.3) and check its package
    /// digests against the published container signatures (local checkout
    /// of the signatures repo and/or the sigs.stagex.tools lookaside).
    Provenance {
        /// Path to the SPDX document (default /provenance.spdx).
        #[arg(long, default_value = "/provenance.spdx")]
        path: PathBuf,
        /// Local checkout of the signatures repo (root containing
        /// stagex/, or the dir with the `<name>@sha256=.../` entries).
        #[arg(long)]
        sigs: Option<PathBuf>,
        /// Lookaside base URL (e.g. https://sigs.stagex.tools).
        #[arg(long)]
        lookaside: Option<String>,
        /// PGP keyring to verify found signatures against (in-process, rPGP).
        #[arg(long)]
        keyring: Option<PathBuf>,
        /// Print every package line, not just a summary.
        #[arg(long)]
        all: bool,
        /// JSON output.
        #[arg(long)]
        json: bool,
        /// Max packages to query for the remote lookaside check.
        #[arg(long, default_value_t = 500)]
        max: usize,
        /// A locally REGENERATED provenance document (after rebuilding at
        /// the pinned commit): compare its per-package digests against
        /// --path. Exit 3 when they differ.
        #[arg(long)]
        compare: Option<PathBuf>,
    },
}

/// `dmext` operations: seal a volume key under a PCR policy (+ optional
/// SEV-SNP gate), or unseal it when both proofs pass.
#[derive(Subcommand)]
enum DmextOp {
    /// Seal a volume key into a TPM2 data object bound to a PCR policy.
    Seal {
        /// TPM kernel character device (default /dev/tpm0).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// Comma-separated PCR indices to bind (default 4,5,7,9).
        #[arg(long, default_value = "4,5,7,9")]
        pcrs: String,
        /// The volume key to seal: raw base64/hex, `@<file>`, or
        /// `-` to read from stdin.
        data: String,
        /// Where to write the sealed blob (JSON).
        #[arg(long, default_value = "/run/dmext.sealed.json")]
        out: PathBuf,
    },
    /// Unseal a volume key (gated on the SEV-SNP proof and the PCR policy).
    Unseal {
        /// TPM kernel character device (default /dev/tpm0).
        #[arg(long, default_value = "/dev/tpm0")]
        device: PathBuf,
        /// The sealed blob (JSON file).
        #[arg(long, default_value = "/run/dmext.sealed.json")]
        blob: PathBuf,
        /// Skip the SEV-SNP gate (TPM PCR policy only). Fails closed
        /// otherwise; use only where the enclave proof is not available.
        #[arg(long)]
        tpm_only: bool,
        /// Print the key to stdout (raw bytes). Default: write to `--out`
        /// and print a summary.
        #[arg(long)]
        print: bool,
        /// Where to write the unsealed key (ignored with `--print`).
        #[arg(long, default_value = "/run/dmext.key")]
        out: PathBuf,
    },
}

fn parse_pcrs(s: &Option<String>) -> Option<Vec<u8>> {
    let s = s.as_deref()?;
    Some(
        s.split(',')
            .map(|x| x.trim().parse::<u8>().expect("bad PCR index"))
            .collect(),
    )
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode a hex or base64 string into bytes (hex wins on even-length input).
fn decode_b64_or_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let t = s.trim();
    if t.len() % 2 == 0 && !t.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex_to_bytes(t);
    }
    Ok(base64::engine::general_purpose::STANDARD
        .decode(t)
        .map_err(|e| anyhow::anyhow!("base64: {e}"))?)
}

fn hex_to_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let b = (0..s.len().div_ceil(2))
        .map(|i| {
            u8::from_str_radix(
                &s[i * 2..i * 2 + 2.min(s.len() - i * 2)],
                16,
            )
        })
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("hex: {e}"))?;
    Ok(b)
}

/// Read the volume key from a `dmext seal` data arg: `-` reads stdin,
/// `@<path>` reads a file, anything else is base64/hex.
fn read_key_arg(data: &str) -> anyhow::Result<Vec<u8>> {
    if data == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().lock().read_to_end(&mut buf)?;
        return Ok(buf);
    }
    if let Some(path) = data.strip_prefix('@') {
        return Ok(std::fs::read(path)?);
    }
    decode_b64_or_hex(data)
}

fn main() -> anyhow::Result<()> {
    // The pgp (rPGP) crate logs WARN while parsing the maintainer keyring --
    // it skips non-critical generic subkey signatures that GnuPG tolerates.
    // That is expected, not an error; keep the CLI output clean. Re-enable
    // with RUST_LOG=pgp=warn if ever diagnosing a keyring.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,pgp=off".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::TpmProbe {
            device,
            tcp,
            unix,
            pcrs,
            raw,
            create_key,
            create_ek,
        } => {
            let (mut tpm, source) = match (tcp, unix) {
                (Some(addr), _) => (
                    Tpm::connect_swtpm_tcp_started(&addr)?,
                    format!("swtpm-tcp://{}", addr),
                ),
                (None, Some(path)) => (
                    Tpm::connect_swtpm_unix_started(&path)?,
                    format!("swtpm-unix://{}", path.display()),
                ),
                (None, None) => (Tpm::open_started(&device)?, device.display().to_string()),
            };
            if let Some(hex_cmd) = raw {
                let cmd: Vec<u8> = (0..hex_cmd.len().div_ceil(2))
                    .map(|i| {
                        u8::from_str_radix(
                            &hex_cmd[i * 2..i * 2 + 2.min(hex_cmd.len() - i * 2)],
                            16,
                        )
                    })
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|e| anyhow::anyhow!("bad hex: {e}"))?;
                let resp = tpm.transfer(&cmd).map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("source={source}");
                println!("cmd  ({}B): {}", cmd.len(), hex_str(&cmd));
                println!("resp ({}B): {}", resp.len(), hex_str(&resp));
                return Ok(());
            }
            if create_key {
                match tpm.create_primary_ecc_sign() {
                    Ok(key) => {
                        println!("source={source}");
                        println!("CreatePrimary OK handle=0x{:08x}", key.handle);
                        println!("public ({}B): {}", key.public.len(), hex_str(&key.public));
                        return Ok(());
                    }
                    Err(e) => {
                        println!("source={source}");
                        println!("CreatePrimary FAILED: {e}");
                        return Ok(());
                    }
                }
            }
            if create_ek {
                // RSA2048 restricted-decrypt template, byte-identical to what
                // the platform tss2 stack marshals (verified working via the
                // esys path): type | nameAlg | attrs | authPolicy | sym
                // {AES,128,CFB} | scheme NULL | keyBits | exponent 0 (=65537)
                // | unique. A restricted decrypt key REQUIRES scheme = NULL
                // (OAEP is rejected).
                let ek_public: [u8; 26] = [
                    0x00, 0x01, // type RSA
                    0x00, 0x0b, // nameAlg SHA256
                    0x00, 0x03, 0x00, 0x72, // attrs userWithAuth|restricted|decrypt
                    0x00, 0x00, // authPolicy size 0
                    // TPMS_RSA_PARMS: symmetric {alg, keyBits, mode}
                    0x00, 0x06, 0x00, 0x80, 0x00, 0x43, // sym AES-128-CFB
                    0x00, 0x10, // scheme NULL (required for restricted decrypt)
                    0x08, 0x00, // keyBits 2048
                    0x00, 0x00, 0x00, 0x00, // exponent 0 (= 65537)
                    0x00, 0x00, // unique size 0
                ];
                let in_sensitive = [0u8, 0, 0, 0]; // userAuth 0, data 0
                let rc = tpm.create_primary_raw_session(
                    0x4000_0007, // SAS auth = TPM_RH_NULL (unbound)
                    bootproof_tpm::session::TPM_SE_HMAC,
                    0x4000_0001, // Owner hierarchy
                    &in_sensitive,
                    &ek_public,
                );
                println!("source={source}");
                match rc {
                    Ok(code) if code == 0 => println!("RSA-decrypt CreatePrimary (Owner, session) OK"),
                    Ok(code) => println!(
                        "RSA-decrypt CreatePrimary (Owner, session) FAILED rc=0x{:04x}",
                        code
                    ),
                    Err(e) => println!("RSA-decrypt CreatePrimary error: {e}"),
                }
                return Ok(());
            }
            tpm_probe::run(tpm, parse_pcrs(&pcrs), &source)?;
        }
        Command::Attest {
            listen,
            state,
            key,
            metadata,
            tcp,
        } => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(bootproof::attest::run(bootproof::attest::Opts {
                    listen,
                    state,
                    key,
                    metadata,
                    tcp,
                }))?;
        }
        Command::Collect { socket, tcp } => {
            // The SOLE device toucher: build the channel registration once and
            // run the collect UDS daemon. Runs on the host (outside gVisor),
            // where /dev/tpm0 and /dev/sev-guest are readable.
            let channels = std::sync::Arc::new(bootproof::attest::build_channels(tcp.as_deref()));
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(bootproof::collect::serve(socket, channels))?;
        }
        Command::Verify {
            target,
            port,
            direct,
            trust,
            pin,
            bundle,
            roots,
            timeout,
            device,
            tcp,
            nv_index,
            json,
            expert,
            pcr_policy,
            user_data,
            min_level,
        } => {
            match target {
                // Local trust tree (default when no target is given).
                None => {
                    let nv_index = u32::from_str_radix(&nv_index, 16)?;
                    std::process::exit(bootproof::trust::run(bootproof::trust::Opts {
                        device,
                        tcp,
                        nv_index,
                        json,
                        expert,
                        pcr_policy,
                        user_data,
                        min_level,
                    })?);
                }
                // Remote client flow.
                Some(target) => {
                    if roots.is_some() {
                        eprintln!("verify: --roots is accepted but embedded roots only, for now");
                    }
                    std::process::exit(bootproof::verify::run(bootproof::verify::Opts {
                        target,
                        port,
                        direct,
                        trust,
                        pin,
                        bundle,
                        json,
                        timeout: std::time::Duration::from_secs(timeout),
                    })?);
                }
            }
        }
        Command::Decrypt { .. } => {
            eprintln!("decrypt: not yet implemented");
            std::process::exit(1);
        }
        Command::Sign { .. } => {
            eprintln!("sign: not yet implemented");
            std::process::exit(1);
        }
        Command::Dmext { op } => match op {
            DmextOp::Seal { device, pcrs, data, out } => {
                let pcr_list: Vec<u8> = pcrs
                    .split(',')
                    .map(|x| x.trim().parse::<u8>().map_err(|e| anyhow::anyhow!("bad PCR index {x:?}: {e}")))
                    .collect::<Result<_, _>>()?;
                let key = read_key_arg(&data)?;
                let blob = bootproof::dmext::seal(&device, &pcr_list, &key, &out)?;
                eprintln!(
                    "seal: wrote {} ({}B key, pcrs {:?}, policy_digest {})",
                    out.display(),
                    key.len(),
                    blob.pcrs,
                    hex_str(&blob.policy_digest.0)
                );
            }
            DmextOp::Unseal { device, blob: blob_path, tpm_only, print, out } => {
                let blob = bootproof::dmext::SealedBlob::load(&blob_path)?;
                eprintln!(
                    "unseal: blob pcrs {:?} policy_digest {} {}",
                    blob.pcrs,
                    hex_str(&blob.policy_digest.0),
                    if tpm_only { "(tpm-only; SNP gate skipped)" } else { "(snp gate on)" }
                );
                let key = bootproof::dmext::unseal(&device, &blob, tpm_only)?;
                if print {
                    // Raw key bytes to stdout.
                    use std::io::Write;
                    std::io::stdout().lock().write_all(&key)?;
                } else {
                    std::fs::write(&out, &key)?;
                    eprintln!(
                        "unseal: OK, {}B key written to {}",
                        key.len(),
                        out.display()
                    );
                }
            }
        },
        Command::TpmBridge { listen, control, device, log: logpath } => {
            use std::io::{Read, Write};
            if let Some(addr) = control {
                std::thread::spawn(move || {
                    let l = match std::net::TcpListener::bind(&addr) {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("tpm-bridge: control bind {addr}: {e}");
                            return;
                        }
                    };
                    eprintln!("tpm-bridge: control on {addr}");
                    for stream in l.incoming() {
                        let mut s = match stream {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("tpm-bridge: control accept ERR {e}");
                                continue;
                            }
                        };
                        let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                        eprintln!("tpm-bridge: control connect from {peer}");
                        let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(2000)));
                        // swtpm control protocol (tcti-swtpm.c): request =
                        // u32 cmd_code + payload; response = u32 rc (0 = ok).
                        // The TCTI uses CMD_SET_LOCALITY (0x05, 1 byte) at
                        // init and CMD_INIT (0x02, 4 bytes) on reset.
                        loop {
                            let mut hdr = [0u8; 4];
                            match s.read_exact(&mut hdr) {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("tpm-bridge: control hdr ERR {e}");
                                    break;
                                }
                            }
                            let cmd = u32::from_be_bytes(hdr);
                            let plen = match cmd {
                                0x02 | 0x12 => 4, // INIT / GET_INFO
                                0x05 => 1,        // SET_LOCALITY
                                _ => 0,
                            };
                            let mut data = vec![0u8; plen];
                            if s.read_exact(&mut data).is_err() {
                                break;
                            }
                            eprintln!(
                                "tpm-bridge: control cmd=0x{cmd:08x}: {}",
                                hex_str(&data)
                            );
                            let wr = s.write_all(&0u32.to_be_bytes()); // rc = success
                            eprintln!("tpm-bridge: control write {wr:?}");
                            let _ = s.flush();
                        }
                        eprintln!("tpm-bridge: control done {peer}");
                    }
                });
            }
            let listener = std::net::TcpListener::bind(&listen)?;
            eprintln!("tpm-bridge: listening on {listen} -> {}", device.display());
            // Open the TPM once; the swtpm TCTI opens a fresh data socket per
            // command (and one throwaway connect at init), so per-connection
            // TPM re-Startup would be wrong.
            let mut tpm = Tpm::open_started(&device)?;
            for stream in listener.incoming() {
                let mut s = stream?;
                let mut logf = logpath
                    .as_ref()
                    .map(|p| std::fs::OpenOptions::new().create(true).append(true).open(p))
                    .transpose()?;
                eprintln!("tpm-bridge: connection from {}", s.peer_addr()?);
                let mut hdr = [0u8; 10];
                loop {
                    // A clean EOF (client closed, e.g. the TCTI's init
                    // sanity-connect) ends this connection, not the bridge.
                    if s.read_exact(&mut hdr).is_err() {
                        break;
                    }
                    let size = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
                    let mut cmd = hdr.to_vec();
                    cmd.resize(size, 0);
                    if s.read_exact(&mut cmd[10..]).is_err() {
                        break;
                    }
                    let resp = match tpm.transfer(&cmd) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("tpm-bridge: tpm ERR {e}");
                            break;
                        }
                    };
                    if let Some(f) = logf.as_mut() {
                        let _ = writeln!(f, "cmd  ({}B): {}", cmd.len(), hex_str(&cmd));
                        let _ = writeln!(f, "resp ({}B): {}", resp.len(), hex_str(&resp));
                    }
                    if s.write_all(&resp).is_err() {
                        break;
                    }
                }
            }
        }
        Command::Nsi {
            device,
            nonce,
            user_data,
            public_key,
            nv_index,
            tcp,
        } => {
            let nv_index = u32::from_str_radix(&nv_index, 16)?;
            let tpm = match &tcp {
                Some(addr) => Tpm::connect_swtpm_tcp_started(addr)?,
                None => Tpm::open_started(&device)?,
            };
            let mut tpm = tpm;
            let nonce = match nonce {
                Some(s) => decode_b64_or_hex(&s)?,
                None => tpm.get_random(32)?,
            };
            let user_data = user_data.map(|s| decode_b64_or_hex(&s)).transpose()?;
            let public_key = public_key
                .map(|p| std::fs::read(&p))
                .transpose()
                .map_err(|e| anyhow::anyhow!("public key: {e}"))?;
            let document = tpm.attestation_document(user_data, Some(nonce), public_key, nv_index)?;
            println!("{}", base64::engine::general_purpose::STANDARD.encode(&document));
        }
        Command::Serve {
            listen,
            device,
            tcp,
            nv_index,
        } => {
            let nv_index = u32::from_str_radix(&nv_index, 16)?;
            let tpm = match &tcp {
                Some(addr) => Tpm::connect_swtpm_tcp_started(addr)?,
                None => Tpm::open_started(&device)?,
            };
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(bootproof::serve::run(bootproof::serve::Opts {
                    listen,
                    tpm,
                    nv_index,
                }))?;
        }
        Command::VerifyNitro {
            doc,
            nonce,
            pcrs,
            time,
            emit_pcrs,
            json,
        } => {
            std::process::exit(verify_nitro::run(verify_nitro::Opts {
                doc,
                nonce,
                pcrs,
                time,
                emit_pcrs,
                json,
            })?);
        }
        Command::NvTest {
            device,
            name_alg,
            attrs,
            size,
            auth,
            index,
            mimic,
            undefine,
            forms,
            seq,
            umatrix,
            raw,
            tcp,
            replay,
            rw,
            rw_sizes,
            clear,
        } => {
            let name_alg = u16::from_str_radix(&name_alg, 16)?;
            let attrs = u32::from_str_radix(&attrs, 16)?;
            let index = u32::from_str_radix(&index, 16)?;
            let auth = auth.map(|s| hex_to_bytes(&s)).transpose()?;
            let open = || match &tcp {
                Some(addr) => Tpm::connect_swtpm_tcp_started(addr),
                None => Tpm::open_started(&device),
            };
            let open_raw = || match &tcp {
                Some(addr) => Tpm::connect_swtpm_tcp(addr),
                None => Tpm::open(&device),
            };
            if clear {
                let mut tpm = open()?;
                let candidates = [
                    0x4000_0009u32,
                    0x4000_0003,
                    0x4000_0002,
                    0x4000_0008,
                    0x4000_0004,
                    0x4000_0000,
                ];
                for (h, rc) in tpm.tpm_clear_probe(&candidates)? {
                    println!("0x{h:08x}: rc=0x{rc:04x}");
                }
            } else if let Some(idx_s) = rw {
                let idx = u32::from_str_radix(idx_s.trim(), 16)?;
                let sizes: Vec<u16> = rw_sizes
                    .split(',')
                    .map(|s| s.trim().parse::<u16>().unwrap_or_else(|_| {
                        eprintln!("[rw] bad size token {s:?}, expected 4..65535");
                        std::process::exit(2)
                    }))
                    .collect();
                let mut tpm = open()?;
                for &sz in &sizes {
                    let (rc_r, body, rc_w) = tpm.nv_rw_probe(idx, sz, sz)?;
                    println!(
                        "sz={sz:>4}: read rc=0x{rc_r:04x} ({}B back) write rc=0x{rc_w:04x}",
                        body
                    );
                }
            } else if let Some(list) = replay {
                let parts: Vec<&str> = list.split_whitespace().collect();
                if parts.len() != 3 && parts.len() != 4 {
                    anyhow::bail!("--replay needs: <sas> <cmd> [area_nonce32 [num_handles]]");
                }
                let sas = hex_to_bytes(parts[0])?;
                let define = hex_to_bytes(parts[1])?;
                let (an, nh) = match parts.len() {
                    2 => (None, 1usize),
                    3 => {
                        // Short 3rd token = num_handles; long = area nonce.
                        if parts[2].len() <= 3 {
                            (None, parts[2].parse::<usize>()?)
                        } else {
                            (Some(hex_to_bytes(parts[2])?), 1)
                        }
                    }
                    4 => (Some(hex_to_bytes(parts[2])?), parts[3].parse::<usize>()?),
                    _ => unreachable!(),
                };
                let mut tpm = open()?;
                for (i, (rc_sas, rc_def)) in tpm.nv_replay(&sas, &define, an.as_deref(), nh)?.iter().enumerate() {
                    println!("{i}: sas rc=0x{rc_sas:04x} define rc=0x{rc_def:04x}");
                }
            } else if let Some(list) = undefine {
                let mut tpm = open()?;
                for part in list.split(',') {
                    let idx = u32::from_str_radix(part.trim(), 16)?;
                    let rc = tpm.nv_undefine_probe(idx)?;
                    println!("undefine {idx}: rc=0x{rc:04x}");
                }
            } else if forms {
                let mut tpm = open()?;
                let (name, rc, handle) = tpm.nv_define_forms(size)?;
                println!("form={name} rc=0x{rc:04x} handle={handle:?}");
            } else if seq {
                let mut tpm = open()?;
                for (tag, rc) in tpm.nv_seq_test(size)? {
                    println!("{tag} rc=0x{rc:04x}");
                }
            } else if let Some(u) = umatrix {
                let idx = u32::from_str_radix(u.trim(), 16)?;
                let mut tpm = open()?;
                for (tag, rc) in tpm.nv_undefine_matrix(idx)? {
                    println!("{tag} rc=0x{rc:04x}");
                }
            } else if let Some(h) = raw {
                let mut tpm = open()?;
                let cmds: Vec<String> = h.split_whitespace().map(|s| s.to_string()).collect();
                let refs: Vec<&str> = cmds.iter().map(|s| s.as_str()).collect();
                let results = tpm.raw_replay(&refs)?;
                for (i, (rc, resp)) in results.iter().enumerate() {
                    println!("{i}: rc=0x{rc:04x} resp={resp}");
                }
            } else if mimic {
                let mut tpm = open_raw()?;
                let (rc, handle) = tpm.nv_define_mimic(size)?;
                println!("rc=0x{rc:04x} handle={handle:?}");
            } else {
                let mut tpm = open()?;
                let (rc, handle) = tpm.nv_define_probe(name_alg, attrs, size, auth.as_deref(), index)?;
                println!("rc=0x{rc:04x} handle={handle:?}");
                if let Some(h) = handle {
                    tpm.flush_context(h).ok();
                }
            }
        }
        Command::Provenance { path, sigs, lookaside, keyring, all, json, max, compare } => {
            std::process::exit(bootproof::provenance::run(bootproof::provenance::Opts {
                path,
                sigs,
                lookaside,
                keyring,
                all,
                json,
                max,
                compare,
            })?);
        }
    }
    Ok(())
}
