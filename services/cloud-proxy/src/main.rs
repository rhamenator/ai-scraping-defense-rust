use asd_core::{health, observability_router, serve, ServiceConfig};
use asd_providers::ModelProvider;
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("cloud-proxy", 8008);
    let app = Router::new()
        .route("/health", get(|| async { health("cloud-proxy").await }))
        .route("/api/chat", post(chat))
        .merge(observability_router("cloud-proxy"));
    serve(app, config).await
}

async fn chat(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    if let Some(provider) = ModelProvider::from_env() {
        match provider.predict(payload.clone()).await {
            Ok(response) => return Json(response),
            Err(exc) => {
                return Json(json!({
                    "status": "error",
                    "provider": "configured",
                    "upstream_status": StatusCode::BAD_GATEWAY.as_u16(),
                    "message": exc.to_string()
                }));
            }
        }
    }
    Json(json!({
        "status": "not_configured",
        "provider": "none",
        "message": "Set CLOUD_MODEL_API_URL and MODEL_PROVIDER to enable upstream model proxying",
        "request": payload
    }))
}
