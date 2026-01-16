// ref: https://github.com/tokio-rs/axum/blob/main/examples/error-handling/src/main.rs

use axum::{
    Json,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::error;

#[derive(Debug, serde::Serialize)]
pub struct ErrorResponse {
    errors: Vec<String>,
}

// NOTE: I thought originally about making a trait similar to IntoResponse, like IntoErrorResponse,
// that could be used to ensure a .status_code() was provided, that ErrorResponse was an extension
// of the response, and that we have a consistent error type. Because of Rust's constraints on
// `impl Trait1 for T where T: Trait2`, it's not possible to dot his conveniently.

impl ErrorResponse {
    pub fn from_error<E: std::error::Error>(error: &E) -> Self {
        let mut errors = vec![error.to_string()];
        let mut source = error.source();
        while let Some(new_error) = source.take() {
            errors.push(new_error.to_string());
            source = new_error.source();
        }

        Self { errors }
    }

    pub fn into_response(self, status_code: impl Into<Option<StatusCode>>) -> Response {
        let status_code = status_code.into().unwrap_or(StatusCode::OK);

        let mut response = (status_code, Json(&self)).into_response();
        response.extensions_mut().insert(Arc::new(self));
        response
    }
}

pub async fn error_logger_middleware(request: Request, next: Next) -> Response {
    let uri = request.uri().clone();
    let response = next.run(request).await;

    if let Some(error_response) = response.extensions().get::<Arc<ErrorResponse>>() {
        // SAFETY: errors is instantiated to have at least one field when created by from_error,
        // and can't be created in any other way. we can safely assume &errors[1..] will not fail
        // with out of range start, even if it is an empty slice.
        let first_error = &error_response.errors[0];
        error!(?uri, "error in request: {first_error}");
        for error in &error_response.errors[1..] {
            error!(" - {error}");
        }
    }

    response
}
