use asd_core::{env_u64, health, is_authorized, observability_router, serve, ServiceConfig};
use axum::{
    extract::{Path, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Clone)]
struct DashboardState {
    metrics: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    registrations: Arc<RwLock<HashSet<String>>>,
    max_installations: usize,
}

impl DashboardState {
    fn from_env() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            registrations: Arc::new(RwLock::new(HashSet::new())),
            max_installations: env_u64("CLOUD_DASHBOARD_MAX_INSTALLATIONS", 10_000)
                .clamp(1, 100_000) as usize,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("cloud-dashboard")?;
    let config = ServiceConfig::from_env("cloud-dashboard", 8006);
    serve(app(DashboardState::from_env()), config).await
}

fn app(state: DashboardState) -> Router {
    Router::new()
        .route("/health", get(|| async { health("cloud-dashboard").await }))
        .route("/register", post(register))
        .route("/metrics", post(push_metrics))
        .route("/metrics/{installation_id}", get(get_metrics))
        .route("/ws/{installation_id}", get(ws))
        .merge(observability_router("cloud-dashboard"))
        .with_state(state)
}

async fn register(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_access(&headers)?;
    let installation_id = validated_installation_id(&payload)?;
    let mut registrations = state.registrations.write().await;
    if !registrations.contains(&installation_id) && registrations.len() >= state.max_installations {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Installation limit reached",
        ));
    }
    registrations.insert(installation_id.clone());
    Ok(Json(
        json!({"status":"registered","installation_id":installation_id}),
    ))
}

async fn push_metrics(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_access(&headers)?;
    let installation_id = validated_installation_id(&payload)?;
    if !state.registrations.read().await.contains(&installation_id) {
        return Err(error(
            StatusCode::NOT_FOUND,
            "Installation is not registered",
        ));
    }
    let metrics = payload
        .get("metrics")
        .cloned()
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "metrics is required"))?;
    state
        .metrics
        .write()
        .await
        .insert(installation_id.clone(), metrics);
    Ok(Json(
        json!({"status":"accepted","installation_id":installation_id}),
    ))
}

async fn get_metrics(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(installation_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_access(&headers)?;
    validate_installation_id(&installation_id)?;
    let payload = state
        .metrics
        .read()
        .await
        .get(&installation_id)
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(Json(
        json!({"installation_id":installation_id,"metrics":payload}),
    ))
}

async fn ws(
    ws: WebSocketUpgrade,
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(installation_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    require_access(&headers)?;
    validate_installation_id(&installation_id)?;
    if !state.registrations.read().await.contains(&installation_id) {
        return Err(error(
            StatusCode::NOT_FOUND,
            "Installation is not registered",
        ));
    }
    Ok(ws.on_upgrade(move |mut socket| async move {
        let _ = socket
            .send(axum::extract::ws::Message::Text(
                format!("{{\"status\":\"connected\",\"installation_id\":\"{installation_id}\"}}")
                    .into(),
            ))
            .await;
    }))
}

fn require_access(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if is_authorized(headers, "CLOUD_DASHBOARD_API_KEY", "JWT_SECRET") {
        Ok(())
    } else {
        Err(error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized; provide x-api-key or a scoped Bearer JWT",
        ))
    }
}

fn validated_installation_id(
    payload: &serde_json::Value,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let value = payload
        .get("installation_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "installation_id is required"))?;
    validate_installation_id(value)?;
    Ok(value.to_string())
}

fn validate_installation_id(value: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid installation_id"));
    }
    Ok(())
}

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({"status":"error","message":message})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_build_with_axum_08() {
        let _ = app(DashboardState::from_env());
    }
}
