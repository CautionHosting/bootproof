//! `bootproof` — unified remote-attestation binary.
//!
//! Subcommands:
//!   attest       — one-shot: collect one Bundle from the collect daemon and
//!              write its JSON to `--out <file>`
//!   verify       — offline bundle verify (`verify <file>`), or challenge a
//!              remote bootproofd node (`verify <remote>`)
//!   attest-fetch — the generic neutral attester: fetch a Bundle from ANY
//!              Bundle-bearing face (framed admin face or HTTP) and verify
//!              it through the registry-driven engine (no credentials, no
//!              platform assumptions)
//!   tpm-probe— debug: read PCRs + properties from a local TPM

mod tpm_probe;

use std::path::{Path, PathBuf};

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
    /// One-shot attest: collect one Bundle from the host-side evidence
    /// collector and write its JSON to this file, then exit. Pairs with
    /// `bootproof verify <file>` for offline attestation. (The TLS node
    /// server and the collect daemon have moved to the enclaved daemon /
    /// bootproofd; this CLI only does the one-shot path.)
    Attest {
        /// Destination for the one-shot Bundle JSON.
        #[arg(long)]
        out: PathBuf,
        /// Optional metadata JSON file.
        #[arg(long)]
        metadata: Option<PathBuf>,
        /// Unix domain socket of the host-side collect daemon (the SOLE
        /// device owner). Every challenge is routed here; the node itself
        /// never opens a device (it runs sandboxed). Unreachable = the Bundle
        /// degrades to no hardware evidence (NOT PROVEN), never a device read.
        #[arg(long, default_value = "/run/bootproof/collect.sock")]
        collect_socket: PathBuf,
        /// File-bridge directory (bind-mounted into the sandbox): instead of
        /// the socket, the challenge/response ride `evidence.challenge` /
        /// `evidence.response` files. Use when the sandbox cannot reach the
        /// host UDS (gVisor). Mutually exclusive with an explicit
        /// `--collect-socket`.
        #[arg(long)]
        bridge_dir: Option<PathBuf>,
    },
    /// The generic, neutral, UNAUTHENTICATED remote attester: fetch a
    /// Bundle from ANY Bundle-bearing face and verify it through the
    /// registry-driven engine. Channels come from the bundle's own
    /// evidence; a channel this build has no verifier for is a loud error,
    /// a channel the node lacks is an honest NOT PROVEN. Exit codes:
    /// 0 = verified with no FAILED channel (NOT PROVEN tolerated, printed
    /// loudly); 1 = a channel FAILED or a --require-channel channel is
    /// absent; 2 = transport/parse/nonce error, nothing was verified.
    AttestFetch {
        /// The framed admin face (host:port, the len-first OP_ATTEST
        /// protocol: seald's admin.sock bridge). The transport is
        /// UNAUTHENTICATED: integrity comes from the bundle's signatures +
        /// the fresh nonce; confidentiality and staleness-resistance are
        /// the tunnel's job (ssh -L). Refuses non-loopback addresses
        /// unless --allow-remote.
        #[arg(long, conflicts_with = "url")]
        frame: Option<String>,
        /// An HTTP(S) bundle face: POST {"nonce": "<base64>"}, answered
        /// with a bare Bundle JSON or an envelope carrying one under a
        /// top-level "bundle" key. https validates the cert chain against
        /// the webpki roots but NOT against the bundle signer identity
        /// (that identity link is the browser verifier's job).
        #[arg(long, conflicts_with = "frame")]
        url: Option<String>,
        /// Allow --frame against a non-loopback address (unauthenticated
        /// transport: know what you are opting into).
        #[arg(long)]
        allow_remote: bool,
        /// Pin the challenge nonce (64 hex chars) instead of a fresh random
        /// one (reproducible captures; the replay guard still applies).
        #[arg(long)]
        nonce_hex: Option<String>,
        /// Fail (exit 1) if this channel is ABSENT from the bundle
        /// (repeatable): turns the honest NOT PROVEN absence into an
        /// operator-selected failure.
        #[arg(long)]
        require_channel: Vec<String>,
        /// Print the fetched bundle JSON before the facts table.
        #[arg(long)]
        bundle: bool,
        /// Request timeout in seconds (each transport phase; default 30).
        #[arg(long, default_value_t = 30)]
        timeout: u64,
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
        Command::Attest { metadata, collect_socket, bridge_dir, out } => {
            // One-shot: write one Bundle to a file and exit (no TLS server).
            // The node server and collect daemon live in the enclaved daemon
            // + bootproofd; this CLI only does the file path.
            // Exactly one transport: an explicit --collect-socket XOR
            // --bridge-dir (neither = the default socket). The socket flag
            // has a default, so the argv presence scan tells us it was typed.
            let argv: Vec<String> = std::env::args().collect();
            let transport = bootproof::collect::transport_from_args(
                &argv,
                "--collect-socket",
                "--bridge-dir",
                Path::new("/run/bootproof/collect.sock"),
                &collect_socket,
                bridge_dir.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let node_id = std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "node".into());
            let platform = bootproof::attest::detect_platform();
            let metadata = match &metadata {
                Some(p) => Some(serde_json::from_str(&std::fs::read_to_string(p)?)?),
                None => None,
            };
            let bundle = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(bootproof::attest::one_shot(
                    &node_id,
                    &platform,
                    &transport,
                    metadata,
                ));
            let json = serde_json::to_string_pretty(&bundle)?;
            std::fs::write(&out, json.as_bytes())?;
            eprintln!(
                "[attest] wrote {} ({} evidence entries) to {}",
                json.len(),
                bundle.evidence.len(),
                out.display()
            );
        }
        Command::AttestFetch {
            frame,
            url,
            allow_remote,
            nonce_hex,
            require_channel,
            bundle,
            timeout,
        } => {
            let opts = bootproof::attest_fetch::FetchOpts {
                frame,
                url,
                allow_remote,
                nonce_hex,
                require_channels: require_channel,
                bundle,
                timeout: std::time::Duration::from_secs(timeout),
            };
            std::process::exit(bootproof::attest_fetch::run(
                &opts,
                &bootproof::verify::render_table,
            )?);
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
                // Remote client flow, or an offline bundle file (P3).
                Some(target) => {
                    if std::path::Path::new(&target).is_file() {
                        std::process::exit(bootproof::verify::run_offline(&target, json)?);
                    }
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
    }
    Ok(())
}
