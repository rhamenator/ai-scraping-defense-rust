use asd_core::{health, observability_router, serve, ServiceConfig};
use axum::{
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Deserialize)]
struct CaptchaSolve {
    answer: Option<String>,
}

#[derive(Deserialize)]
struct CaptchaVerify {
    token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("captcha-service", 8005);
    let app = Router::new()
        .route("/health", get(|| async { health("captcha-service").await }))
        .route("/challenge", get(challenge))
        .route("/solve", post(solve))
        .route("/verify", post(verify))
        .merge(observability_router("captcha-service"));
    serve(app, config).await
}

async fn challenge() -> Html<&'static str> {
    Html(
        r#"<html><body><form method="post" action="/solve"><label>Type human</label><input name="answer"/></form></body></html>"#,
    )
}

async fn solve(Json(payload): Json<CaptchaSolve>) -> Json<serde_json::Value> {
    let ok = payload
        .answer
        .as_deref()
        .map(|answer| answer.eq_ignore_ascii_case("human"))
        .unwrap_or(false);
    Json(json!({
        "success": ok,
        "token": ok.then(|| Uuid::new_v4().to_string())
    }))
}

async fn verify(Json(payload): Json<CaptchaVerify>) -> Json<serde_json::Value> {
    Json(json!({
        "success": payload.token.as_deref().map(|token| !token.is_empty()).unwrap_or(false)
    }))
}
