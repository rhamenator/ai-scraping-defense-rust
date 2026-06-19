use asd_core::{health, observability_router, serve, ServiceConfig};
use axum::{
    extract::{Path, State, WebSocketUpgrade},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
struct DashboardState {
    metrics: Arc<RwLock<HashMap<String, serde_json::Value>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("cloud-dashboard", 8006);
    let state = DashboardState::default();
    let app = Router::new()
        .route("/health", get(|| async { health("cloud-dashboard").await }))
        .route("/register", post(register))
        .route("/metrics", post(push_metrics))
        .route("/metrics/:installation_id", get(get_metrics))
        .route("/ws/:installation_id", get(ws))
        .merge(observability_router("cloud-dashboard"))
        .with_state(state);
    serve(app, config).await
}

async fn register(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(json!({"status":"registered","installation":payload}))
}

async fn push_metrics(
    State(state): State<DashboardState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let installation_id = payload
        .get("installation_id")
        .and_then(|value| value.as_str())
        .unwrap_or("default")
        .to_string();
    state
        .metrics
        .write()
        .await
        .insert(installation_id.clone(), payload);
    Json(json!({"status":"accepted","installation_id":installation_id}))
}

async fn get_metrics(
    State(state): State<DashboardState>,
    Path(installation_id): Path<String>,
) -> Json<serde_json::Value> {
    let payload = state
        .metrics
        .read()
        .await
        .get(&installation_id)
        .cloned()
        .unwrap_or_else(|| json!({}));
    Json(json!({"installation_id":installation_id,"metrics":payload}))
}

async fn ws(ws: WebSocketUpgrade, Path(installation_id): Path<String>) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        let _ = socket
            .send(axum::extract::ws::Message::Text(format!(
                "{{\"status\":\"connected\",\"installation_id\":\"{installation_id}\"}}"
            )))
            .await;
    })
}
