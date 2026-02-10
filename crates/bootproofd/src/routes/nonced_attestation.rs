use crate::AppState;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::{panic::Location, sync::Arc};

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

#[derive(Debug, serde::Serialize)]
pub enum NoncedAttestationErrorKind {
    InvalidData,
    InvalidNonce,
    AttestationGeneration,
}

#[derive(Debug, thiserror::Error)]
#[error("unable to get nonced attestation: {kind:?} (at: {location:?})")]
pub struct NoncedAttestationError {
    #[source]
    source: Box<dyn std::error::Error>,
    kind: NoncedAttestationErrorKind,
    location: &'static Location<'static>,
    status_code: StatusCode,
}

impl From<crate::versioned_json_file::VersionedJsonFileError> for NoncedAttestationError {
    #[track_caller]
    fn from(value: crate::versioned_json_file::VersionedJsonFileError) -> Self {
        Self {
            source: Box::new(value),
            kind: NoncedAttestationErrorKind::InvalidData,
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            location: Location::caller(),
        }
    }
}

impl From<crate::attestation::AttestationGenerationError> for NoncedAttestationError {
    #[track_caller]
    fn from(value: crate::attestation::AttestationGenerationError) -> Self {
        Self {
            source: Box::new(value),
            kind: NoncedAttestationErrorKind::AttestationGeneration,
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            location: Location::caller(),
        }
    }
}

impl From<base64::DecodeError> for NoncedAttestationError {
    #[track_caller]
    fn from(value: base64::DecodeError) -> Self {
        Self {
            source: Box::new(value),
            kind: NoncedAttestationErrorKind::InvalidNonce,
            status_code: StatusCode::BAD_REQUEST,
            location: Location::caller(),
        }
    }
}

impl IntoResponse for NoncedAttestationError {
    fn into_response(self) -> axum::response::Response {
        crate::error_handling::ErrorResponse::from_error(&self).into_response(self.status_code)
    }
}

pub async fn generate_nonced_attestation(
    State(app_state): State<Arc<AppState>>,
    Json(NoncedAttestationRequest { nonce }): Json<NoncedAttestationRequest>,
) -> Result<Json<NoncedAttestationResponse>, NoncedAttestationError> {
    let manifest = app_state
        .manifest
        .lock()
        .expect("manifest unpoisoned")
        .get()?
        .clone();

    let mut metadata_opt = app_state.metadata.lock().expect("metadata lock");
    let metadata_bytes = if let Some(metadata) = metadata_opt.as_mut() {
        serde_json::to_vec(metadata.get()?).expect("should be able to write parsed JSON")
    } else {
        let new_file = crate::get_metadata()?;
        if let Some(mut metadata) = new_file {
            let bytes =
                serde_json::to_vec(metadata.get()?).expect("should be able to write parsed JSON");
            let _ = metadata_opt.insert(metadata);
            bytes
        } else {
            b"{}".to_vec()
        }
    };

    let nonce = BASE64_STANDARD.decode(nonce)?;

    // TODO: hash metadata and sign a hash of the metadata?
    // This is failure prone with the assumption you could read the metadata without having to
    // verify the bootproof, but we'll leave that as a problem for bootproof-client.
    let document_bytes = crate::attestation::generate_attestation(
        Some(&metadata_bytes),
        Some(&nonce),
        // NOTE: We never use the public key field. Should it be removed? We should probably stick
        // it as a known field in the user data.
        None,
    )?;
    let document = BASE64_STANDARD.encode(document_bytes);

    Ok(Json(NoncedAttestationResponse { document, manifest }))
}
