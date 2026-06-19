use asd_core::{
    health, is_authorized, observability_router, pg_connect_from_env, record_security_event, serve,
    BlocklistState, IpAction, ServiceConfig,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    blocklist: BlocklistState,
    pg: Option<Arc<tokio_postgres::Client>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("public-blocklist", 8011);
    let state = AppState {
        blocklist: BlocklistState::from_env().await,
        pg: pg_connect_from_env().await.map(Arc::new),
    };
    let app = Router::new()
        .route(
            "/health",
            get(|| async { health("public-blocklist").await }),
        )
        .route("/list", get(list))
        .route("/list/auth", get(list_auth))
        .route("/report", post(report))
        .merge(observability_router("public-blocklist"))
        .with_state(state);
    serve(app, config).await
}

async fn list(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"blocked": state.blocklist.blocked().await}))
}

async fn list_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "PUBLIC_BLOCKLIST_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    Ok(list(State(state)).await)
}

async fn report(
    State(state): State<AppState>,
    Json(action): Json<IpAction>,
) -> Json<serde_json::Value> {
    if let Some(ip) = action.ip {
        let reason = action.reason.unwrap_or_else(|| "community_report".into());
        state.blocklist.flag(ip.clone(), reason.clone()).await;
        record_security_event(
            state.pg.as_deref(),
            "public_blocklist_report",
            &ip,
            json!({"ip":ip,"reason":reason}),
        )
        .await;
        Json(json!({"status":"accepted","ip":ip}))
    } else {
        Json(json!({"status":"error","message":"ip required"}))
    }
}

fn unauthorized() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"status":"error","message":"Unauthorized"})),
    )
}
