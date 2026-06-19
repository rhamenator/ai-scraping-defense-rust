use asd_core::{health, observability_router, serve, ServiceConfig};
use axum::{routing::get, Json, Router};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("config-recommender", 8007);
    let app = Router::new()
        .route(
            "/health",
            get(|| async { health("config-recommender").await }),
        )
        .route("/recommendations", get(recommendations))
        .merge(observability_router("config-recommender"));
    serve(app, config).await
}

async fn recommendations() -> Json<serde_json::Value> {
    Json(json!({
        "rate_limit_per_minute": 120,
        "escalation_threshold": 0.70,
        "tarpit_threshold": 0.82,
        "block_threshold": 0.92,
        "source": "rust-baseline"
    }))
}
