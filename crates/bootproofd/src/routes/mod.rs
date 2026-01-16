pub mod nonced_attestation;

pub mod health {
    use axum::Json;
    use serde_json::{Value, json};

    pub async fn health() -> Json<Value> {
        Json(json!({
            "status": "ok",
            "service": "attestation"
        }))
    }
}
