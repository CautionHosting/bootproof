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
    #[arg(long, default_value = "/run/enclaved/sock")]
    socket: std::path::PathBuf,

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
    let opts = bootproof::attest::Opts {
        listen: cli.listen,
        state: cli.state,
        key: cli.key,
        metadata: cli.metadata,
        collect_socket: cli.socket,
    };

    tracing::info!(
        listen = %opts.listen,
        socket = %opts.collect_socket.display(),
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
        assert!(cli.key.is_none());
        assert!(cli.metadata.is_none());
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
        assert_eq!(cli.key.as_deref(), Some(std::path::Path::new("/tmp/key.pem")));
        assert_eq!(
            cli.metadata.as_deref(),
            Some(std::path::Path::new("/tmp/meta.json"))
        );
    }
}
