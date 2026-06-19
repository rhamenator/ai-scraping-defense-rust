use asd_core::{
    health, observability_router, pg_connect_from_env, record_security_event, serve,
    verify_hmac_sha256, BlocklistState, ServiceConfig,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    config: ServiceConfig,
    blocklist: BlocklistState,
    pg: Option<Arc<tokio_postgres::Client>>,
}

#[derive(Debug, Deserialize)]
struct WebhookAction {
    action: String,
    ip: Option<String>,
    reason: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("ai-service", 8001);
    let state = AppState {
        config: config.clone(),
        blocklist: BlocklistState::from_env().await,
        pg: pg_connect_from_env().await.map(Arc::new),
    };
    let app = Router::new()
        .route("/health", get(|| async { health("ai-service").await }))
        .route("/webhook", post(webhook))
        .merge(observability_router("ai-service"))
        .with_state(state);
    serve(app, config).await
}

async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(secret) = &state.config.webhook_shared_secret {
        let signature = headers
            .get("x-signature")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !verify_hmac_sha256(secret, &body, signature) {
            return Err(error(StatusCode::UNAUTHORIZED, "Unauthorized"));
        }
    }
    let action: WebhookAction = serde_json::from_slice(&body)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "Invalid payload"))?;
    let Some(ip) = action.ip.as_deref() else {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid payload"));
    };
    match action.action.as_str() {
        "block_ip" => {
            state.blocklist.block(ip.to_string()).await;
            record_security_event(
                state.pg.as_deref(),
                "webhook_block_ip",
                ip,
                json!({"ip":ip,"reason":action.reason}),
            )
            .await;
            Ok(Json(
                json!({"status":"success","message":format!("IP {ip} added to blocklist.")}),
            ))
        }
        "allow_ip" => {
            state.blocklist.allow(ip).await;
            record_security_event(
                state.pg.as_deref(),
                "webhook_allow_ip",
                ip,
                json!({"ip":ip}),
            )
            .await;
            Ok(Json(
                json!({"status":"success","message":format!("IP {ip} removed from blocklist.")}),
            ))
        }
        "flag_ip" => {
            let reason = action.reason.unwrap_or_else(|| "flagged".into());
            state.blocklist.flag(ip.to_string(), reason.clone()).await;
            record_security_event(
                state.pg.as_deref(),
                "webhook_flag_ip",
                ip,
                json!({"ip":ip,"reason":reason}),
            )
            .await;
            Ok(Json(
                json!({"status":"success","message":format!("IP {ip} flagged.")}),
            ))
        }
        "unflag_ip" => {
            state.blocklist.unflag(ip).await;
            record_security_event(
                state.pg.as_deref(),
                "webhook_unflag_ip",
                ip,
                json!({"ip":ip}),
            )
            .await;
            Ok(Json(
                json!({"status":"success","message":format!("IP {ip} unflagged.")}),
            ))
        }
        _ => Err(error(StatusCode::BAD_REQUEST, "Invalid payload")),
    }
}

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({"status":"error","message":message})))
}
