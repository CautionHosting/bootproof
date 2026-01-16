//! bootproof daemon

use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use axum::{Router, routing};
use tracing::debug;

mod attestation;
mod error_handling;
mod routes;
mod versioned_json_file;

use versioned_json_file::VersionedJsonFile;

#[derive(Debug)]
struct AppState {
    metadata: Option<Mutex<VersionedJsonFile>>,
    manifest: Mutex<VersionedJsonFile>,
}

// NOTE: Once execd supports checking that manifest.json and optionally metadata.json exist
// before starting bootproofd, these values should be once cell'd.
static MANIFEST_FILE: &str = "/manifest.json";
static METADATA_FILE: &str = "/metadata.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    debug!("reading metadata");
    let metadata = match VersionedJsonFile::new(METADATA_FILE) {
        Ok(vjf) => Some(vjf),
        Err(e) => {
            if e.kind == versioned_json_file::VersionedJsonFileErrorKind::Io
                && let Some(io_error) = e.source.downcast_ref::<std::io::Error>()
                && io_error.kind() == std::io::ErrorKind::NotFound
            {
                debug!("no metadata found, will use empty object");
                None
            } else {
                return Err(e.into());
            }
        }
    };

    debug!("reading manifest");
    let manifest = VersionedJsonFile::new(MANIFEST_FILE)?;

    debug!("setting up app state");
    let app_state = AppState {
        metadata: metadata.map(Mutex::new),
        manifest: Mutex::new(manifest),
    };

    debug!("launching bootproofd");
    run_basic_server(app_state).await?;

    Ok(())
}

async fn run_basic_server(app_state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(app_state);

    let app = Router::new()
        .route(
            "/health",
            routing::get(routes::health::health),
        )
        .route(
            "/attestation",
            routing::post(routes::nonced_attestation::generate_nonced_attestation),
        )
        .layer(axum::middleware::from_fn(
            error_handling::error_logger_middleware,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let listen_addr =
        std::env::var("BOOTPROOFD_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8082".into());
    debug!(%listen_addr, "binding listener");
    let listener = TcpListener::bind(&listen_addr).await?;

    debug!("serving single-attestation server");
    axum::serve(listener, app).await?;

    Ok(())
}
