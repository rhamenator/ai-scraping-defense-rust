use asd_core::{health, observability_router, serve, ServiceConfig};
use asd_providers::ModelProvider;
use axum::{
    extract::ConnectInfo,
    http::HeaderMap,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("cloud-proxy")?;
    let config = ServiceConfig::from_env("cloud-proxy", 8008);
    let app = Router::new()
        .route("/health", get(|| async { health("cloud-proxy").await }))
        .route("/api/chat", post(chat))
        .merge(observability_router("cloud-proxy"));
    serve(app, config).await
}

async fn chat(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let payload = bind_trusted_tls_fingerprint(payload, peer, &headers);
    if let Some(provider) = ModelProvider::from_env() {
        match provider.predict(payload.clone()).await {
            Ok(response) => return Json(response),
            Err(exc) => {
                return Json(json!({
                    "status": "error",
                    "provider": "configured",
                    "upstream_status": StatusCode::BAD_GATEWAY.as_u16(),
                    "message": exc.to_string()
                }));
            }
        }
    }
    Json(json!({
        "status": "not_configured",
        "provider": "none",
        "message": "Set CLOUD_MODEL_API_URL and MODEL_PROVIDER to enable upstream model proxying",
        "request": payload
    }))
}

fn bind_trusted_tls_fingerprint(
    mut payload: serde_json::Value,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> serde_json::Value {
    let Some(object) = payload.as_object_mut() else {
        return payload;
    };
    for field in [
        "tls_ja3",
        "tls_ja4",
        "tls_fingerprint_source",
        "tls_fingerprint_attestation",
        "tls_fingerprint_verified",
    ] {
        object.remove(field);
    }
    let Some(fingerprint) = asd_core::trusted_tls_fingerprint(peer.ip(), headers) else {
        return payload;
    };
    let Some(client_ip) = asd_core::trusted_originating_client_ip(peer.ip(), headers) else {
        return payload;
    };
    let method = object
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("GET")
        .to_string();
    let path = object
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let key = std::env::var("TLS_FINGERPRINT_ATTESTATION_KEY").unwrap_or_default();
    let Some(attestation) = asd_core::create_tls_fingerprint_attestation(
        &key,
        chrono::Utc::now().timestamp(),
        &client_ip,
        &method,
        &path,
        &fingerprint,
    ) else {
        return payload;
    };
    object.insert("ip".into(), json!(client_ip));
    if let Some(ja3) = fingerprint.ja3 {
        object.insert("tls_ja3".into(), json!(ja3));
    }
    if let Some(ja4) = fingerprint.ja4 {
        object.insert("tls_ja4".into(), json!(ja4));
    }
    object.insert("tls_fingerprint_source".into(), json!(fingerprint.source));
    object.insert("tls_fingerprint_attestation".into(), json!(attestation));
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn direct_client_tls_claims_are_removed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let payload = json!({
            "ip": "198.51.100.7",
            "method": "GET",
            "path": "/products",
            "tls_ja3": "72a589da586844d7f0818ce684948eea",
            "tls_fingerprint_source": "client"
        });
        let output = bind_trusted_tls_fingerprint(
            payload,
            "198.51.100.7:443".parse().unwrap(),
            &HeaderMap::new(),
        );
        assert!(output.get("tls_ja3").is_none());
        assert!(output.get("tls_fingerprint_source").is_none());
    }

    #[test]
    fn trusted_envoy_values_are_bound_and_client_claims_overwritten() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SECURITY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8");
        std::env::set_var(
            "TLS_FINGERPRINT_ATTESTATION_KEY",
            "0123456789abcdef0123456789abcdef",
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        headers.insert(
            "x-asd-tls-ja3",
            "72a589da586844d7f0818ce684948eea".parse().unwrap(),
        );
        headers.insert(
            "x-asd-tls-ja4",
            "t13d1516h2_8daaf6152771_e5627efa2ab1".parse().unwrap(),
        );
        let output = bind_trusted_tls_fingerprint(
            json!({
                "ip": "203.0.113.99",
                "method": "GET",
                "path": "/products",
                "tls_fingerprint_source": "client-claim"
            }),
            "10.0.0.2:443".parse().unwrap(),
            &headers,
        );
        assert_eq!(output["ip"], "198.51.100.7");
        assert_eq!(output["tls_fingerprint_source"], "envoy");
        assert!(output["tls_fingerprint_attestation"]
            .as_str()
            .is_some_and(|token| token.starts_with("v1:")));
        std::env::remove_var("SECURITY_TRUSTED_PROXY_CIDRS");
        std::env::remove_var("TLS_FINGERPRINT_ATTESTATION_KEY");
    }
}
