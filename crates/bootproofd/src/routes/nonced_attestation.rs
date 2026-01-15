use crate::{log_error, AppState};

use std::sync::Arc;
use axum::{Json, extract::State, http::StatusCode};

#[allow(clippy::wildcard_imports)]
use base64::prelude::*;

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
pub async fn generate_nonced_attestation(
    State(app_state): State<Arc<AppState>>,
    Json(NoncedAttestationRequest { nonce }): Json<NoncedAttestationRequest>,
) -> Result<Json<NoncedAttestationResponse>, StatusCode> {
    let manifest = match app_state.manifest.lock().expect("manifest unpoisoned").get() {
        Ok(manifest) => manifest.clone(),
        Err(error) => {
            log_error(error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let metadata_bytes = if let Some(metadata) = &app_state.metadata {
        match metadata.lock().expect("metadata unpoisoned").get() {
            Ok(metadata) => serde_json::to_vec(metadata).expect("parse valid, write valid"),
            Err(error) => {
                log_error(error);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    } else {
        b"{}".to_vec()
    };

    let nonce = BASE64_STANDARD.decode(nonce).expect("add some error handling");

    // TODO: hash metadata and sign a hash of the metadata?
    // This is failure prone with the assumption you could read the metadata without having to
    // verify the bootproof, but we'll leave that as a problem for bootproof-client.
    let document = match crate::attestation::generate_attestation(
        Some(&metadata_bytes),
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

