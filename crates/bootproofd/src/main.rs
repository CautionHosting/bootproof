//! bootproofd — the enclave's network-facing attestation face.
//!
//! Thin CLI over `bootproof::attest`: the ONLY process in the enclave that
//! knows HTTP. It runs inside the gVisor sandbox and holds NO channels and
//! opens NO devices — every attestation challenge is routed to the enclaved
//! evidence daemon's Unix socket (`--socket`, the SOLE device owner) over the
//! frozen Phase-0 collect protocol. When the daemon is unreachable, the
//! Bundle degrades honestly to no hardware evidence (NOT PROVEN), never a 500.

use clap::Parser;

/// The enclave's network-facing attestation face.
#[derive(Parser)]
#[command(
    name = "bootproofd",
    version,
    about = "Serves TLS /health, /info, /attestation; routes every challenge to the enclaved evidence daemon's Unix socket"
)]
struct Cli {
    /// Listen address for the TLS attestation API.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: String,

    /// Identity dir: the image keeps the TLS identity + TPM keys there for
    /// pin stability.
    #[arg(long, default_value = "/home/bootproof")]
    state: std::path::PathBuf,

    /// The enclaved evidence daemon's Unix socket (the SOLE device owner).
    /// Default transport; at most one of `--socket` (explicit) and
    /// `--bridge-dir` may be given — neither typed = this default.
    #[arg(long, default_value = "/run/enclaved/sock")]
    socket: std::path::PathBuf,

    /// File-bridge directory (bind-mounted into the sandbox): instead of the
    /// socket, the challenge/response ride `evidence.challenge` /
    /// `evidence.response` files in this directory. Use when the sandbox
    /// cannot reach the host UDS (gVisor). Mutually exclusive with an
    /// explicit `--socket`.
    #[arg(long)]
    bridge_dir: Option<std::path::PathBuf>,

    /// Static TLS key (PEM PKCS8 P-384). If set, used in place of the
    /// state-dir identity (for reproducible images).
    #[arg(long)]
    key: Option<std::path::PathBuf>,

    /// Optional metadata JSON file.
    #[arg(long)]
    metadata: Option<std::path::PathBuf>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Must precede any rustls config the node builds (ring provider).
    bootproof::attest::install_crypto_provider();

    let cli = Cli::parse();
    // Exactly one transport: an explicit --socket XOR --bridge-dir (neither
    // typed = the default socket, byte-identical to the pre-bridge behavior).
    // --socket has a default, so the argv presence scan tells us it was typed.
    let argv: Vec<String> = std::env::args().collect();
    let transport = match bootproof::collect::transport_from_args(
        &argv,
        "--socket",
        "--bridge-dir",
        &cli.socket,
        &cli.socket,
        cli.bridge_dir.as_deref(),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("bootproofd: {e}");
            std::process::exit(2);
        }
    };

    let opts = bootproof::attest::Opts {
        listen: cli.listen,
        state: cli.state,
        key: cli.key,
        metadata: cli.metadata,
        transport,
    };

    tracing::info!(
        listen = %opts.listen,
        transport = ?opts.transport,
        "bootproofd: launching attest node"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = rt.block_on(bootproof::attest::run(opts)) {
        eprintln!("bootproofd: {e:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_match_the_image_contract() {
        let cli = Cli::try_parse_from(["bootproofd"]).unwrap();
        assert_eq!(cli.listen, "0.0.0.0:443");
        assert_eq!(cli.state, std::path::PathBuf::from("/home/bootproof"));
        assert_eq!(cli.socket, std::path::PathBuf::from("/run/enclaved/sock"));
        assert!(cli.bridge_dir.is_none());
        assert!(cli.key.is_none());
        assert!(cli.metadata.is_none());
    }

    #[test]
    fn exactly_one_transport_is_enforced() {
        let default = std::path::Path::new("/run/enclaved/sock");
        // Neither typed -> the default socket (the pre-bridge behavior).
        match bootproof::collect::resolve_transport(default, None, None).unwrap() {
            bootproof::collect::Transport::Socket(s) => {
                assert_eq!(s, std::path::PathBuf::from("/run/enclaved/sock"))
            }
            other => panic!("default must be the socket transport, got {other:?}"),
        }
        // Only the socket typed -> that socket.
        match bootproof::collect::resolve_transport(
            default,
            Some(std::path::Path::new("/tmp/evid.sock")),
            None,
        )
        .unwrap()
        {
            bootproof::collect::Transport::Socket(s) => {
                assert_eq!(s, std::path::PathBuf::from("/tmp/evid.sock"))
            }
            other => panic!("socket flag must select the socket transport, got {other:?}"),
        }
        // Only the bridge typed -> the bridge dir.
        match bootproof::collect::resolve_transport(
            default,
            None,
            Some(std::path::Path::new("/run/enclaved")),
        )
        .unwrap()
        {
            bootproof::collect::Transport::Bridge(d) => {
                assert_eq!(d, std::path::PathBuf::from("/run/enclaved"))
            }
            other => panic!("bridge flag must select the bridge transport, got {other:?}"),
        }
        // Both typed -> hard error (exactly one transport).
        let err = bootproof::collect::resolve_transport(
            default,
            Some(std::path::Path::new("/tmp/evid.sock")),
            Some(std::path::Path::new("/run/enclaved")),
        )
        .err()
        .expect("both transports must be rejected");
        assert!(err.contains("exactly one transport"), "error: {err}");
    }

    #[test]
    fn cli_accepts_all_flags() {
        let cli = Cli::try_parse_from([
            "bootproofd",
            "--listen",
            "127.0.0.1:8443",
            "--state",
            "/tmp/state",
            "--socket",
            "/tmp/evid.sock",
            "--key",
            "/tmp/key.pem",
            "--metadata",
            "/tmp/meta.json",
        ])
        .unwrap();
        assert_eq!(cli.listen, "127.0.0.1:8443");
        assert_eq!(cli.state, std::path::PathBuf::from("/tmp/state"));
        assert_eq!(cli.socket, std::path::PathBuf::from("/tmp/evid.sock"));
        assert!(cli.bridge_dir.is_none());
        assert_eq!(cli.key.as_deref(), Some(std::path::Path::new("/tmp/key.pem")));
        assert_eq!(
            cli.metadata.as_deref(),
            Some(std::path::Path::new("/tmp/meta.json"))
        );
    }

    #[test]
    fn cli_accepts_bridge_dir() {
        let cli = Cli::try_parse_from(["bootproofd", "--bridge-dir", "/run/enclaved"]).unwrap();
        // --socket keeps its default value; value_source (checked at resolve
        // time) is what marks it as not-explicit, so the bridge wins.
        assert_eq!(cli.socket, std::path::PathBuf::from("/run/enclaved/sock"));
        assert_eq!(
            cli.bridge_dir.as_deref(),
            Some(std::path::Path::new("/run/enclaved"))
        );
    }
}
