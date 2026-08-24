use asd_core::{
    env_string, env_u64, health, is_authorized, observability_router, serve, ServiceConfig,
};
use axum::{
    http::{HeaderMap, StatusCode},
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
    let _telemetry = asd_core::init_tracing("prompt-router")?;
    let config = ServiceConfig::from_env("prompt-router", 8009);
    let app = Router::new()
        .route("/health", get(|| async { health("prompt-router").await }))
        .route("/route", post(route_prompt))
        .merge(observability_router("prompt-router"));
    serve(app, config).await
}

async fn route_prompt(
    headers: HeaderMap,
    Json(req): Json<RouteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "PROMPT_ROUTER_API_KEY", "JWT_SECRET") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                json!({"status":"error","message":"Unauthorized; configure PROMPT_ROUTER_API_KEY with scripts/configure_credentials.py"}),
            ),
        ));
    }
    let max_local_tokens = env_u64("MAX_LOCAL_TOKENS", 2048);
    let requested = req.max_tokens.unwrap_or(0);
    let target = if requested > max_local_tokens {
        "cloud-proxy".to_string()
    } else {
        env_string("LOCAL_MODEL_TARGET", "local-inference")
    };
    if target == "cloud-proxy" {
        let url = env_string("CLOUD_PROXY_URL", "http://127.0.0.1:8008/api/chat");
        let cloud_proxy_api_key = env_string("CLOUD_PROXY_API_KEY", "");
        let request = reqwest::Client::new()
            .post(&url)
            .header("x-api-key", cloud_proxy_api_key)
            .json(&req);
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let body = response
                    .json::<serde_json::Value>()
                    .await
                    .unwrap_or_else(|_| json!({}));
                return proxy_http_response(status, target, body);
            }
            Err(exc) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "status": "error",
                        "target": target,
                        "message": exc.to_string()
                    })),
                ));
            }
        }
    }
    Ok(Json(json!({
        "status": "success",
        "target": target,
        "prompt_len": req.prompt.as_deref().unwrap_or("").len(),
        "max_local_tokens": max_local_tokens
    })))
}

fn proxy_http_response(
    upstream_status: reqwest::StatusCode,
    target: String,
    body: serde_json::Value,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let payload = Json(json!({
        "status": if upstream_status.is_success() { "success" } else { "error" },
        "target": target,
        "upstream_status": upstream_status.as_u16(),
        "response": body
    }));
    if upstream_status.is_success() {
        return Ok(payload);
    }
    Err((StatusCode::BAD_GATEWAY, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_failure_returns_bad_gateway() {
        let result = proxy_http_response(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "cloud-proxy".to_string(),
            json!({"status": "error"}),
        );
        assert!(matches!(result, Err((StatusCode::BAD_GATEWAY, _))));
    }
}
