//! bootproof daemon

use std::{error::Error, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;

#[allow(clippy::wildcard_imports)]
use base64::prelude::*;

use axum::{Json, Router, extract::State, http::StatusCode, routing};
use tracing::{debug, error};

mod attestation;

fn log_error<E: Error>(error: E) {
    error!("could not generate attestation: {error}");
    let mut source = error.source();
    while let Some(new_error) = source.take() {
        error!("- caused by: {new_error}");
        source = new_error.source();
    }
}

#[derive(Debug)]
struct AppState {}

#[derive(Debug)]
pub enum DataReadErrorKind {
    BadRead,
    ParseJson,
}

#[derive(Debug, thiserror::Error)]
#[error("Could not read JSON file: {kind:?}")]
pub struct DataReadError {
    #[source]
    source: Box<dyn std::error::Error>,
    kind: DataReadErrorKind,
    file: PathBuf,
}

// NOTE: Once execd supports checking that manifest.json and optionally metadata.json exist,
// these values should be once cell'd.
static MANIFEST_FILE: &str = "/manifest.json";
static METADATA_FILE: &str = "/metadata.json";

fn read_manifest() -> Result<serde_json::Value, DataReadError> {
    debug!("Reading manifest");
    let manifest = std::fs::read_to_string(MANIFEST_FILE).map_err(|source| DataReadError {
        source: Box::new(source),
        kind: DataReadErrorKind::BadRead,
        file: std::path::PathBuf::from(MANIFEST_FILE),
    })?;

    debug!("Parsing manifest");
    let manifest_value: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|source| DataReadError {
            source: Box::new(source),
            kind: DataReadErrorKind::ParseJson,
            file: std::path::PathBuf::from(MANIFEST_FILE),
        })?;

    Ok(manifest_value)
}

fn read_metadata() -> Result<serde_json::Value, DataReadError> {
    // This file might not exist. In the event it doesn't, we return an empty object.
    if !std::fs::exists(METADATA_FILE).unwrap_or(false) {
        return Ok(serde_json::Value::Object(serde_json::Map::default()));
    }

    debug!("Reading metadata");
    let metadata = std::fs::read_to_string(METADATA_FILE).map_err(|source| DataReadError {
        source: Box::new(source),
        kind: DataReadErrorKind::BadRead,
        file: std::path::PathBuf::from(METADATA_FILE),
    })?;

    debug!("Parsing metadata");
    let metadata_value: serde_json::Value =
        serde_json::from_str(&metadata).map_err(|source| DataReadError {
            source: Box::new(source),
            kind: DataReadErrorKind::ParseJson,
            file: std::path::PathBuf::from(METADATA_FILE),
        })?;

    Ok(metadata_value)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    debug!("setting up app state");
    let app_state = AppState {};

    debug!("launching bootproofd");
    run_basic_server(app_state).await?;

    Ok(())
}

// TODO: These should be split into a separate crate, so bootproof-client can build its own
// NoncedAttestationRequest and deserialize NoncedAttestationResponse

/// A nonced attestation request.
#[derive(Debug, serde::Deserialize)]
pub struct NoncedAttestationRequest {
    /// A base64 encoded nonce.
    pub nonce: String,
}

/// A nonced attestation response.
#[derive(Debug, serde::Serialize)]
pub struct NoncedAttestationResponse {
    // NOTE: Encoding with JSON means b64strings or hexstrings are the most compact encodings.
    // If we were to move to CBOR, we can start using bytevecs.
    /// A base64 encoded attestation document.
    pub document: String,

    /// The manifest used to build the enclave.
    pub manifest: serde_json::Value,
}

// TODO: We should impl an error here and have that error impl IntoResponse of JSON combined w/ the
// StatusCode.
//
// Currently, an error returns empty body?
async fn generate_nonced_attestation(
    State(_app_state): State<Arc<AppState>>,
    Json(NoncedAttestationRequest { nonce }): Json<NoncedAttestationRequest>,
) -> Result<Json<NoncedAttestationResponse>, StatusCode> {
    let manifest = match read_manifest() {
        Ok(manifest) => manifest,
        Err(error) => {
            log_error(error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let metadata = match read_metadata() {
        Ok(metadata) => serde_json::to_vec(&metadata).expect("it was already parsed json :("),
        Err(error) => {
            // NOTE: read_metadata returns an empty object if the metadata file doesn't exist
            // If we've hit this point, there's an actual error.
            log_error(error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let nonce = BASE64_STANDARD.decode(nonce).expect("add some error handling");

    // TODO: hash metadata and sign a hash of the metadata?
    // This is failure prone with the assumption you could read the metadata without having to
    // verify the bootproof, but we'll leave that as a problem for bootproof-client.
    let document = match attestation::generate_attestation(
        Some(&metadata),
        Some(&nonce),
        // NOTE: We never use the public key field. Should it be removed? We should probably stick
        // it as a known field in the user data.
        None,
    ) {
        Ok(bytes) => BASE64_STANDARD.encode(bytes),
        Err(error) => {
            log_error(error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Ok(Json(NoncedAttestationResponse { document, manifest }))
}

async fn run_basic_server(app_state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(app_state);

    let app = Router::new()
        .route("/attestation", routing::post(generate_nonced_attestation))
        .with_state(state);

    let listen_addr =
        std::env::var("BOOTPROOFD_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8082".into());
    debug!(%listen_addr, "binding listener");
    let listener = TcpListener::bind(&listen_addr).await?;

    debug!("serving single-attestation server");
    axum::serve(listener, app).await?;

    Ok(())
}
