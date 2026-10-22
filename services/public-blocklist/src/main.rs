use asd_core::{
    has_valid_api_key, health, is_authorized, is_blockable_client_ip, observability_router,
    pg_connect_from_env, record_security_event, serve, AuditStore, BlocklistState, IpAction,
    ServiceConfig,
};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{env, net::IpAddr, sync::Arc};

#[derive(Clone)]
struct AppState {
    blocklist: BlocklistState,
    audit: AuditStore,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("public-blocklist")?;
    let config = ServiceConfig::from_env("public-blocklist", 8011);
    let pg = pg_connect_from_env().await.map(Arc::new);
    let state = AppState {
        blocklist: BlocklistState::from_env().await?,
        audit: AuditStore::from_env(pg).await?,
    };
    let app = Router::new()
        .route(
            "/health",
            get(|| async { health("public-blocklist").await }),
        )
        .route("/list", get(list))
        .route("/list/auth", get(list_auth))
        .route(
            "/report",
            post(report).route_layer(middleware::from_fn(require_report_key)),
        )
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
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(ip) = action.ip.and_then(|ip| ip.parse::<IpAddr>().ok()) {
        if !is_reportable_ip(ip) || !is_blockable_client_ip(&ip.to_string()) {
            return Err(bad_request("public client IP required"));
        }
        let reason = action.reason.unwrap_or_else(|| "community_report".into());
        if reason.trim().is_empty() || reason.len() > 256 {
            return Err(bad_request("reason must be 1 to 256 bytes"));
        }
        let ip = ip.to_string();
        if !state.blocklist.flag(ip.clone(), reason.clone()).await {
            return Err(bad_request("public client IP required"));
        }
        record_security_event(
            &state.audit,
            "public_blocklist_report",
            &ip,
            json!({"ip":ip,"reason":reason}),
        )
        .await;
        Ok(Json(json!({"status":"accepted","ip":ip})))
    } else {
        Err(bad_request("valid IP required"))
    }
}

fn is_reportable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
    }
}

async fn require_report_key(request: Request, next: Next) -> Response {
    let Ok(expected) = env::var("PUBLIC_BLOCKLIST_API_KEY") else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"error","message":"API key not configured"})),
        )
            .into_response();
    };
    if expected.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"error","message":"API key not configured"})),
        )
            .into_response();
    }
    if !has_valid_api_key(request.headers(), &expected) {
        return unauthorized().into_response();
    }
    next.run(request).await
}

fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status":"error","message":message})),
    )
}

fn unauthorized() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"status":"error","message":"Unauthorized"})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn report_requires_key_before_parsing_and_validates_content() {
        env::set_var("PUBLIC_BLOCKLIST_API_KEY", "test-only-secret");
        let state = AppState {
            blocklist: BlocklistState::default(),
            audit: AuditStore::Disabled,
        };
        let app = Router::new()
            .route(
                "/report",
                post(report).route_layer(middleware::from_fn(require_report_key)),
            )
            .with_state(state.clone());

        for (key, body, expected) in [
            (None, "not-json", StatusCode::UNAUTHORIZED),
            (Some("wrong"), "{}", StatusCode::UNAUTHORIZED),
            (
                Some("test-only-secret"),
                "not-json",
                StatusCode::BAD_REQUEST,
            ),
            (
                Some("test-only-secret"),
                "{\"ip\":\"bad-ip\"}",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let mut request = Request::builder().method("POST").uri("/report");
            if let Some(key) = key {
                request = request.header("x-api-key", key);
            }
            let response = app
                .clone()
                .oneshot(
                    request
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        assert_eq!(state.blocklist.stats().await.flagged_count, 0);

        for ip in ["127.0.0.1", "10.0.0.1", "::1", "fe80::1"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/report")
                        .header("x-api-key", "test-only-secret")
                        .header("content-type", "application/json")
                        .body(Body::from(json!({"ip":ip}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{ip}");
        }

        let too_long = json!({"ip":"198.51.100.23","reason":"x".repeat(257)});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/report")
                    .header("x-api-key", "test-only-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(too_long.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.blocklist.stats().await.flagged_count, 0);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/report")
                    .header("x-api-key", "test-only-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"ip":"198.51.100.23","reason":"test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.blocklist.stats().await.flagged_count, 1);

        env::remove_var("PUBLIC_BLOCKLIST_API_KEY");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/report")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
