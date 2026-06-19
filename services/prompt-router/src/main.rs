use asd_core::{env_string, env_u64, health, observability_router, serve, ServiceConfig};
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize, serde::Serialize)]
struct RouteRequest {
    prompt: Option<String>,
    max_tokens: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("prompt-router", 8009);
    let app = Router::new()
        .route("/health", get(|| async { health("prompt-router").await }))
        .route("/route", post(route_prompt))
        .merge(observability_router("prompt-router"));
    serve(app, config).await
}

async fn route_prompt(Json(req): Json<RouteRequest>) -> Json<serde_json::Value> {
    let max_local_tokens = env_u64("MAX_LOCAL_TOKENS", 2048);
    let requested = req.max_tokens.unwrap_or(0);
    let target = if requested > max_local_tokens {
        "cloud-proxy".to_string()
    } else {
        env_string("LOCAL_MODEL_TARGET", "local-inference")
    };
    if target == "cloud-proxy" {
        let url = env_string("CLOUD_PROXY_URL", "http://127.0.0.1:8008/api/chat");
        match reqwest::Client::new().post(&url).json(&req).send().await {
            Ok(response) => {
                let status = response.status();
                let body = response
                    .json::<serde_json::Value>()
                    .await
                    .unwrap_or_else(|_| json!({}));
                return Json(json!({
                    "status": if status.is_success() { "success" } else { "error" },
                    "target": target,
                    "upstream_status": status.as_u16(),
                    "response": body
                }));
            }
            Err(exc) => {
                return Json(json!({
                    "status": "error",
                    "target": target,
                    "message": exc.to_string()
                }));
            }
        }
    }
    Json(json!({
        "status": "success",
        "target": target,
        "prompt_len": req.prompt.as_deref().unwrap_or("").len(),
        "max_local_tokens": max_local_tokens
    }))
}
