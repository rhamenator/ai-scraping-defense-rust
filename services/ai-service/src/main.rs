use asd_core::{
    health, observability_router, pg_connect_from_env, record_security_event, serve,
    verify_hmac_sha256, AuditStore, BlocklistState, ServiceConfig,
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
    audit: AuditStore,
}

#[derive(Debug, Deserialize)]
struct WebhookAction {
    action: String,
    ip: Option<String>,
    reason: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("ai-service")?;
    let config = ServiceConfig::from_env("ai-service", 8001);
    let pg = pg_connect_from_env().await.map(Arc::new);
    let state = AppState {
        config: config.clone(),
        blocklist: BlocklistState::from_env().await?,
        audit: AuditStore::from_env(pg).await?,
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
    let Some(secret) = &state.config.webhook_shared_secret else {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "WEBHOOK_SHARED_SECRET is not configured; run scripts/configure_credentials.py",
        ));
    };
    let signature = headers
        .get("x-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !verify_hmac_sha256(secret, &body, signature) {
        return Err(error(StatusCode::UNAUTHORIZED, "Unauthorized"));
    }
    let action: WebhookAction = serde_json::from_slice(&body)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "Invalid payload"))?;
    let Some(ip) = action.ip.as_deref() else {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid payload"));
    };
    match action.action.as_str() {
        "block_ip" => {
            if !state.blocklist.block(ip.to_string()).await {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "IP is invalid or belongs to trusted proxy infrastructure",
                ));
            }
            record_security_event(
                &state.audit,
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
            record_security_event(&state.audit, "webhook_allow_ip", ip, json!({"ip":ip})).await;
            Ok(Json(
                json!({"status":"success","message":format!("IP {ip} removed from blocklist.")}),
            ))
        }
        "flag_ip" => {
            let reason = action.reason.unwrap_or_else(|| "flagged".into());
            if !state.blocklist.flag(ip.to_string(), reason.clone()).await {
                return Err(error(StatusCode::BAD_REQUEST, "Invalid IP"));
            }
            record_security_event(
                &state.audit,
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
            record_security_event(&state.audit, "webhook_unflag_ip", ip, json!({"ip":ip})).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn state(webhook_shared_secret: Option<&str>) -> AppState {
        AppState {
            config: ServiceConfig {
                service_name: "ai-service-test".into(),
                port: 0,
                webhook_shared_secret: webhook_shared_secret.map(str::to_string),
                escalation_threshold: 0.7,
                throttle_threshold: 0.72,
                tarpit_threshold: 0.82,
                block_threshold: 0.92,
            },
            blocklist: BlocklistState::default(),
            audit: AuditStore::Disabled,
        }
    }

    #[tokio::test]
    async fn configured_webhook_secret_rejects_unsigned_requests() {
        let result = webhook(
            State(state(Some("test-webhook-secret"))),
            HeaderMap::new(),
            Bytes::from_static(br#"{"action":"block_ip","ip":"198.51.100.11"}"#),
        )
        .await;

        assert!(matches!(result, Err((StatusCode::UNAUTHORIZED, _))));
    }

    #[tokio::test]
    async fn malformed_and_incomplete_payloads_fail_closed() {
        let malformed_body = Bytes::from_static(b"not-json");
        let mut malformed_headers = HeaderMap::new();
        malformed_headers.insert(
            "x-signature",
            asd_core::hmac_sha256_hex("test-webhook-secret", &malformed_body)
                .parse()
                .unwrap(),
        );
        let malformed = webhook(
            State(state(Some("test-webhook-secret"))),
            malformed_headers,
            malformed_body,
        )
        .await;
        assert!(matches!(malformed, Err((StatusCode::BAD_REQUEST, _))));

        let missing_ip_body = Bytes::from_static(br#"{"action":"block_ip"}"#);
        let mut missing_ip_headers = HeaderMap::new();
        missing_ip_headers.insert(
            "x-signature",
            asd_core::hmac_sha256_hex("test-webhook-secret", &missing_ip_body)
                .parse()
                .unwrap(),
        );
        let missing_ip = webhook(
            State(state(Some("test-webhook-secret"))),
            missing_ip_headers,
            missing_ip_body,
        )
        .await;
        assert!(matches!(missing_ip, Err((StatusCode::BAD_REQUEST, _))));
    }

    #[tokio::test]
    async fn block_and_allow_actions_change_blocklist_state() {
        let state = state(Some("test-webhook-secret"));
        let ip = "198.51.100.12";
        let body = Bytes::from(format!(r#"{{"action":"block_ip","ip":"{ip}"}}"#));
        let signature = asd_core::hmac_sha256_hex("test-webhook-secret", &body);
        let mut headers = HeaderMap::new();
        headers.insert("x-signature", signature.parse().unwrap());
        let _ = webhook(State(state.clone()), headers, body)
            .await
            .expect("block action should succeed");
        assert!(state.blocklist.contains(ip).await);

        let body = Bytes::from(format!(r#"{{"action":"allow_ip","ip":"{ip}"}}"#));
        let signature = asd_core::hmac_sha256_hex("test-webhook-secret", &body);
        let mut headers = HeaderMap::new();
        headers.insert("x-signature", signature.parse().unwrap());
        let _ = webhook(State(state.clone()), headers, body)
            .await
            .expect("allow action should succeed");
        assert!(!state.blocklist.contains(ip).await);
    }

    #[tokio::test]
    async fn invalid_ip_is_never_added_to_blocklist() {
        let state = state(Some("test-webhook-secret"));
        let body = Bytes::from_static(br#"{"action":"block_ip","ip":"not-an-ip"}"#);
        let signature = asd_core::hmac_sha256_hex("test-webhook-secret", &body);
        let mut headers = HeaderMap::new();
        headers.insert("x-signature", signature.parse().unwrap());
        let result = webhook(State(state.clone()), headers, body).await;

        assert!(matches!(result, Err((StatusCode::BAD_REQUEST, _))));
        assert!(state.blocklist.blocked().await.is_empty());
    }

    #[tokio::test]
    async fn invalid_flag_request_is_rejected_without_state_change() {
        let state = state(Some("test-webhook-secret"));
        let body = Bytes::from_static(br#"{"action":"flag_ip","ip":"not-an-ip"}"#);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-signature",
            asd_core::hmac_sha256_hex("test-webhook-secret", &body)
                .parse()
                .unwrap(),
        );
        let result = webhook(State(state.clone()), headers, body).await;

        assert!(matches!(result, Err((StatusCode::BAD_REQUEST, _))));
        assert_eq!(state.blocklist.stats().await.flagged_count, 0);
    }
}
