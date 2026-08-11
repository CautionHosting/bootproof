//! bootproof daemon

use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use axum::{
    Router,
    http::{Method, header::CONTENT_TYPE},
    routing,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::debug;

mod attestation;
mod error_handling;
mod routes;
mod versioned_json_file;

use versioned_json_file::VersionedJsonFile;

#[derive(Debug)]
struct AppState {
    metadata: Mutex<Option<VersionedJsonFile>>,
    manifest: Mutex<VersionedJsonFile>,
}

// NOTE: Once execd supports checking that manifest.json and optionally metadata.json exist
// before starting bootproofd, these values should be once cell'd.
static MANIFEST_FILE: &str = "/manifest.json";
static METADATA_FILE: &str = "/metadata.json";

fn attestation_cors() -> CorsLayer {
    // Attestations are public, cryptographically authenticated evidence. Allow browser-based
    // verifiers to fetch them without enabling CORS on any application route.
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST])
        .allow_headers([CONTENT_TYPE])
}

// TODO: move this into AppState?
// it's currently being called in main() and generate_nonced_attestation(), which is not the best.
// or we can just delay until we ship execd they're OnceCell'd.
fn get_metadata() -> Result<Option<VersionedJsonFile>, versioned_json_file::VersionedJsonFileError>
{
    match VersionedJsonFile::new(METADATA_FILE) {
        Ok(vjf) => Ok(Some(vjf)),
        Err(e) => {
            if e.kind == versioned_json_file::VersionedJsonFileErrorKind::Io
                && let Some(io_error) = e.source.downcast_ref::<std::io::Error>()
                && io_error.kind() == std::io::ErrorKind::NotFound
            {
                debug!("no metadata found, will use empty object");
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    debug!("reading metadata");
    let metadata = get_metadata()?;

    debug!("reading manifest");
    let manifest = VersionedJsonFile::new(MANIFEST_FILE)?;

    debug!("setting up app state");
    let app_state = AppState {
        metadata: Mutex::new(metadata),
        manifest: Mutex::new(manifest),
    };

    debug!("launching bootproofd");
    run_basic_server(app_state)?;

    Ok(())
}

#[tokio::main]
async fn run_basic_server(app_state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(app_state);

    let app = Router::new()
        .route("/health", routing::get(routes::health::health))
        .route(
            "/attestation",
            routing::post(routes::nonced_attestation::generate_nonced_attestation)
                .layer(attestation_cors()),
        )
        .layer(axum::middleware::from_fn(
            error_handling::error_logger_middleware,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let listen_addr =
        std::env::var("BOOTPROOFD_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:49502".into());
    debug!(%listen_addr, "binding listener");
    let listener = TcpListener::bind(&listen_addr).await?;

    debug!("serving single-attestation server");
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route(
                "/attestation",
                routing::post(|| async { StatusCode::NO_CONTENT }),
            )
            .layer(attestation_cors())
    }

    #[tokio::test]
    async fn attestation_preflight_allows_browser_verifiers() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/attestation")
                    .header(header::ORIGIN, "https://verifier.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&header::HeaderValue::from_static("*"))
        );
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_METHODS),
            Some(&header::HeaderValue::from_static("POST"))
        );
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_HEADERS),
            Some(&header::HeaderValue::from_static("content-type"))
        );
    }

    #[tokio::test]
    async fn attestation_post_is_readable_cross_origin() {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/attestation")
                    .header(header::ORIGIN, "https://verifier.example")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&header::HeaderValue::from_static("*"))
        );
    }
}
