use anyhow::Context as _;
use axum::{
    extract::{connect_info::IntoMakeServiceWithConnectInfo, Request},
    http::HeaderMap,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::{
    SpanKind, Status, TraceContextExt as _, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context as OtelContext, KeyValue};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, Resource};
use redis::{AsyncCommands, ConnectionAddr, ConnectionInfo, RedisConnectionInfo};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet},
    env,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tokio_postgres::{Client as PgClient, NoTls};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type HmacSha256 = Hmac<Sha256>;
static OTEL_EXPORT_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub service_name: String,
    pub port: u16,
    pub webhook_shared_secret: Option<String>,
    pub escalation_threshold: f64,
    pub throttle_threshold: f64,
    pub tarpit_threshold: f64,
    pub block_threshold: f64,
}

impl ServiceConfig {
    pub fn from_env(service_name: &str, default_port: u16) -> Self {
        let env_prefix = service_name.replace('-', "_").to_ascii_uppercase();
        Self {
            service_name: service_name.to_string(),
            port: env_u16(&format!("{env_prefix}_PORT"), default_port),
            webhook_shared_secret: env::var("WEBHOOK_SHARED_SECRET")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            escalation_threshold: env_f64("ESCALATION_THRESHOLD", 0.70),
            throttle_threshold: env_f64("ESCALATION_THROTTLE_THRESHOLD", 0.72),
            tarpit_threshold: env_f64("ESCALATION_TARPIT_THRESHOLD", 0.82),
            block_threshold: env_f64("ESCALATION_BLOCK_THRESHOLD", 0.92),
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port))
    }
}

#[derive(Clone, Default)]
pub struct BlocklistState {
    blocked: Arc<RwLock<HashSet<String>>>,
    flagged: Arc<RwLock<HashMap<String, String>>>,
    redis: Option<redis::Client>,
    blocklist_key: String,
    flag_prefix: String,
}

impl BlocklistState {
    pub async fn from_env() -> Self {
        let mut state = Self {
            blocklist_key: tenant_key("blocklist"),
            flag_prefix: tenant_key("ip_flag:"),
            ..Self::default()
        };
        if env::var("REDIS_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("false"))
            .unwrap_or(false)
        {
            return state;
        }

        match redis_client_from_env("REDIS_DB_BLOCKLIST", 0) {
            Ok(client) => match client.get_multiplexed_async_connection().await {
                Ok(mut con) => {
                    let ping: redis::RedisResult<String> =
                        redis::cmd("PING").query_async(&mut con).await;
                    if ping.is_ok() {
                        tracing::info!("connected to Redis-backed blocklist store");
                        state.redis = Some(client);
                    }
                }
                Err(exc) => {
                    tracing::warn!(error = %exc, "Redis unavailable; using in-memory blocklist store")
                }
            },
            Err(exc) => {
                tracing::warn!(error = %exc, "Redis config invalid; using in-memory blocklist store")
            }
        }
        state
    }

    pub async fn block(&self, ip: impl Into<String>) -> bool {
        let ip = ip.into();
        if !is_blockable_client_ip(&ip) {
            tracing::warn!(ip = %ip, "refusing to block an invalid or trusted infrastructure IP");
            return false;
        }
        self.blocked.write().await.insert(ip.clone());
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<usize> = con.sadd(&self.blocklist_key, &ip).await;
                if let Err(exc) = result {
                    tracing::warn!(error = %exc, ip = %ip, "failed to persist block to Redis; in-memory block remains active");
                }
            }
        }
        true
    }

    pub async fn allow(&self, ip: &str) {
        self.blocked.write().await.remove(ip);
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<usize> = con.srem(&self.blocklist_key, ip).await;
                if let Err(exc) = result {
                    tracing::warn!(error = %exc, ip, "failed to remove block from Redis; in-memory block was removed");
                }
            }
        }
    }

    pub async fn flag(&self, ip: impl Into<String>, reason: impl Into<String>) {
        let ip = ip.into();
        let reason = reason.into();
        self.flagged
            .write()
            .await
            .insert(ip.clone(), reason.clone());
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<()> = con
                    .set(format!("{}{}", self.flag_prefix, ip), &reason)
                    .await;
                if let Err(exc) = result {
                    tracing::warn!(error = %exc, ip = %ip, "failed to persist flag to Redis; in-memory flag remains active");
                }
            }
        }
    }

    pub async fn unflag(&self, ip: &str) {
        self.flagged.write().await.remove(ip);
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<usize> =
                    con.del(format!("{}{}", self.flag_prefix, ip)).await;
                if let Err(exc) = result {
                    tracing::warn!(error = %exc, ip, "failed to remove flag from Redis; in-memory flag was removed");
                }
            }
        }
    }

    pub async fn contains(&self, ip: &str) -> bool {
        if self.blocked.read().await.contains(ip) {
            if let Some(client) = &self.redis {
                if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                    let _: redis::RedisResult<usize> = con.sadd(&self.blocklist_key, ip).await;
                }
            }
            return true;
        }
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<bool> = con.sismember(&self.blocklist_key, ip).await;
                if let Ok(value) = result {
                    if value {
                        self.blocked.write().await.insert(ip.to_string());
                    }
                    return value;
                }
            }
        }
        self.blocked.read().await.contains(ip)
    }

    pub async fn blocked(&self) -> Vec<String> {
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<Vec<String>> =
                    con.smembers(&self.blocklist_key).await;
                if let Ok(mut entries) = result {
                    entries.sort();
                    return entries;
                }
            }
        }
        let mut entries = self
            .blocked
            .read()
            .await
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    pub async fn stats(&self) -> BlocklistStats {
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let blocked_count: redis::RedisResult<usize> = con.scard(&self.blocklist_key).await;
                if let Ok(blocked_count) = blocked_count {
                    let pattern = format!("{}*", self.flag_prefix);
                    let flagged_count = match con.scan_match::<_, String>(pattern).await {
                        Ok(mut entries) => {
                            let mut count = 0;
                            while entries.next_item().await.is_some() {
                                count += 1;
                            }
                            count
                        }
                        Err(exc) => {
                            tracing::warn!(error = %exc, "failed to scan flagged IP keys");
                            0
                        }
                    };
                    return BlocklistStats {
                        blocked_count,
                        flagged_count,
                    };
                }
            }
        }
        BlocklistStats {
            blocked_count: self.blocked.read().await.len(),
            flagged_count: self.flagged.read().await.len(),
        }
    }
}

pub fn redis_client_from_env(
    db_env_var: &str,
    default_db: u16,
) -> redis::RedisResult<redis::Client> {
    let host = env_string("REDIS_HOST", "localhost");
    let port = env_u16("REDIS_PORT", 6379);
    let db = env_u16(db_env_var, default_db);
    redis::Client::open(ConnectionInfo {
        addr: ConnectionAddr::Tcp(host, port),
        redis: RedisConnectionInfo {
            db: i64::from(db),
            username: env::var("REDIS_USERNAME")
                .ok()
                .filter(|value| !value.is_empty()),
            password: redis_password(),
            ..RedisConnectionInfo::default()
        },
    })
}

fn redis_password() -> Option<String> {
    if let Ok(path) = env::var("REDIS_PASSWORD_FILE") {
        if let Ok(value) = std::fs::read_to_string(path) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    env::var("REDIS_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Serialize)]
pub struct BlocklistStats {
    pub blocked_count: usize,
    pub flagged_count: usize,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: String,
    pub timestamp_utc: DateTime<Utc>,
}

pub async fn health(service: &str) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: service.to_string(),
        timestamp_utc: Utc::now(),
    })
}

pub fn observability_router<S>(service: &'static str) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/observability/health",
            get(move || async move { health(service).await }),
        )
        .route(
            "/observability/metrics",
            get(move || async move { metrics_text(service, &[]) }),
        )
        .route(
            "/observability/performance/insights",
            get(move || async move {
                Json(serde_json::json!({
                    "service": service,
                    "insights": [],
                    "status": "ok"
                }))
            }),
        )
        .route(
            "/observability/performance/predictions",
            get(move || async move {
                Json(serde_json::json!({
                    "service": service,
                    "predictions": [],
                    "status": "ok"
                }))
            }),
        )
        .route(
            "/observability/performance/history",
            get(move || async move {
                Json(serde_json::json!({
                    "service": service,
                    "history": [],
                    "status": "ok"
                }))
            }),
        )
}

#[derive(Debug, Serialize)]
pub struct ApiMessage {
    pub status: String,
    pub message: String,
}

pub fn message(status: impl Into<String>, message: impl Into<String>) -> Json<ApiMessage> {
    Json(ApiMessage {
        status: status.into(),
        message: message.into(),
    })
}

pub fn verify_hmac_sha256(secret: &str, body: &[u8], signature_hex: &str) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    constant_time_eq(expected.as_bytes(), signature_hex.as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsFingerprint {
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub source: String,
}

pub fn normalize_ja3(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    (candidate.len() == 32 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(candidate)
}

pub fn normalize_ja4(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    let parts = candidate.split('_').collect::<Vec<_>>();
    (parts.len() == 3
        && parts[0].len() == 10
        && parts[0]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && parts[1].len() == 12
        && parts[2].len() == 12
        && parts[1]
            .bytes()
            .chain(parts[2].bytes())
            .all(|byte| byte.is_ascii_hexdigit()))
    .then_some(candidate)
}

pub fn normalize_tls_source(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    (!candidate.is_empty()
        && candidate.len() <= 32
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(candidate)
}

fn tls_attestation_message(
    issued_at: i64,
    client_ip: &str,
    method: &str,
    path: &str,
    fingerprint: &TlsFingerprint,
) -> Option<Vec<u8>> {
    let timestamp = issued_at.to_string();
    let client_ip = client_ip.trim().to_ascii_lowercase();
    let method = method.trim().to_ascii_uppercase();
    let fields = [
        "v1",
        timestamp.as_str(),
        client_ip.as_str(),
        method.as_str(),
        path,
        fingerprint.ja3.as_deref().unwrap_or(""),
        fingerprint.ja4.as_deref().unwrap_or(""),
        fingerprint.source.as_str(),
    ];
    if fields
        .iter()
        .any(|value| value.contains(['\n', '\r', '\0']))
    {
        return None;
    }
    Some(fields.join("\n").into_bytes())
}

pub fn create_tls_fingerprint_attestation(
    key: &str,
    issued_at: i64,
    client_ip: &str,
    method: &str,
    path: &str,
    fingerprint: &TlsFingerprint,
) -> Option<String> {
    if key.len() < 32 {
        return None;
    }
    let fingerprint = TlsFingerprint {
        ja3: normalize_ja3(fingerprint.ja3.as_deref()),
        ja4: normalize_ja4(fingerprint.ja4.as_deref()),
        source: normalize_tls_source(Some(&fingerprint.source))?,
    };
    if fingerprint.ja3.is_none() && fingerprint.ja4.is_none() {
        return None;
    }
    let message = tls_attestation_message(issued_at, client_ip, method, path, &fingerprint)?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).ok()?;
    mac.update(&message);
    Some(format!(
        "v1:{issued_at}:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

pub struct TlsAttestationContext<'a> {
    pub now: i64,
    pub client_ip: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub fingerprint: &'a TlsFingerprint,
}

pub fn verify_tls_fingerprint_attestation(
    token: Option<&str>,
    key: &str,
    max_age_seconds: u64,
    context: &TlsAttestationContext<'_>,
) -> bool {
    verify_tls_fingerprint_attestation_with_keys(token, &[key], max_age_seconds, context)
}

pub fn verify_tls_fingerprint_attestation_with_keys(
    token: Option<&str>,
    keys: &[&str],
    max_age_seconds: u64,
    context: &TlsAttestationContext<'_>,
) -> bool {
    let Some(token) = token else {
        return false;
    };
    if max_age_seconds == 0 || !keys.iter().any(|key| key.len() >= 32) {
        return false;
    }
    let parts = token.trim().to_ascii_lowercase();
    let mut parts = parts.split(':');
    if parts.next() != Some("v1") {
        return false;
    }
    let Some(issued_at) = parts.next().and_then(|value| value.parse::<i64>().ok()) else {
        return false;
    };
    let Some(signature) = parts.next() else {
        return false;
    };
    if parts.next().is_some()
        || signature.len() != 64
        || !signature.bytes().all(|byte| byte.is_ascii_hexdigit())
        || context.now.abs_diff(issued_at) > max_age_seconds
    {
        return false;
    }
    let mut verified = false;
    for key in keys.iter().filter(|key| key.len() >= 32) {
        if let Some(expected) = create_tls_fingerprint_attestation(
            key,
            issued_at,
            context.client_ip,
            context.method,
            context.path,
            context.fingerprint,
        ) {
            let expected = expected.rsplit(':').next().unwrap_or_default();
            verified |= constant_time_eq(expected.as_bytes(), signature.as_bytes());
        }
    }
    verified
}

pub fn trusted_tls_fingerprint(
    peer_ip: std::net::IpAddr,
    headers: &HeaderMap,
) -> Option<TlsFingerprint> {
    let (ja3_header, ja4_header, source) =
        if ip_in_configured_ranges(peer_ip, &["SECURITY_CDN_TRUSTED_PROXY_CIDRS"]) {
            ("cf-ja3-hash", "cf-ja4", "cloudflare")
        } else if ip_in_configured_ranges(peer_ip, &["SECURITY_TRUSTED_PROXY_CIDRS"]) {
            ("x-asd-tls-ja3", "x-asd-tls-ja4", "envoy")
        } else {
            return None;
        };
    let fingerprint = TlsFingerprint {
        ja3: normalize_ja3(
            headers
                .get(ja3_header)
                .and_then(|value| value.to_str().ok()),
        ),
        ja4: normalize_ja4(
            headers
                .get(ja4_header)
                .and_then(|value| value.to_str().ok()),
        ),
        source: source.to_string(),
    };
    (fingerprint.ja3.is_some() || fingerprint.ja4.is_some()).then_some(fingerprint)
}

pub fn trusted_originating_client_ip(
    peer_ip: std::net::IpAddr,
    headers: &HeaderMap,
) -> Option<String> {
    if ip_in_configured_ranges(peer_ip, &["SECURITY_CDN_TRUSTED_PROXY_CIDRS"]) {
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<std::net::IpAddr>().ok())
        {
            return Some(ip.to_string());
        }
    }
    if !ip_in_configured_ranges(
        peer_ip,
        &[
            "SECURITY_CDN_TRUSTED_PROXY_CIDRS",
            "SECURITY_TRUSTED_PROXY_CIDRS",
        ],
    ) {
        return None;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .iter()
        .flat_map(|value| value.split(',').rev())
        .filter_map(|value| value.trim().parse::<std::net::IpAddr>().ok())
        .find(|candidate| {
            !ip_in_configured_ranges(
                *candidate,
                &[
                    "SECURITY_CDN_TRUSTED_PROXY_CIDRS",
                    "SECURITY_TRUSTED_PROXY_CIDRS",
                ],
            )
        })
        .map(|ip| ip.to_string())
}

pub fn is_authorized(headers: &HeaderMap, api_key_env: &str, jwt_secret_env: &str) -> bool {
    let expected_api_key = env::var(api_key_env).ok().filter(|value| !value.is_empty());
    let jwt_secret = env::var(jwt_secret_env)
        .ok()
        .filter(|value| !value.is_empty());
    if expected_api_key.is_none() && jwt_secret.is_none() {
        tracing::error!(
            api_key_env,
            jwt_secret_env,
            "authorization secrets are not configured; denying request"
        );
        return false;
    }

    if let Some(expected) = expected_api_key {
        let provided = headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
            return true;
        }
    }

    if let Some(secret) = jwt_secret {
        let token = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        return verify_hs256_jwt(token, &secret);
    }

    false
}

pub fn verify_hs256_jwt(token: &str, secret: &str) -> bool {
    decode_hs256_jwt(token, secret).is_some()
}

pub fn decode_hs256_jwt(token: &str, secret: &str) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let signing_input = format!("{header}.{payload}");
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return None;
    };
    mac.update(signing_input.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        return None;
    }

    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(payload) else {
        return None;
    };
    let Ok(payload_json) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
        return None;
    };
    if let Some(exp) = payload_json.get("exp").and_then(|value| value.as_i64()) {
        if Utc::now().timestamp() >= exp {
            return None;
        }
    }
    Some(payload_json)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = &self.provider {
            if let Err(exc) = provider.shutdown() {
                tracing::error!(error = %exc, "failed to flush OTLP traces during shutdown");
            }
        }
    }
}

pub fn init_tracing(service_name: &str) -> anyhow::Result<TelemetryGuard> {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,tower_http=info".into());
    let endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty());

    let provider = if let Some(endpoint) = endpoint {
        let uri = endpoint
            .parse::<axum::http::Uri>()
            .context("OTEL_EXPORTER_OTLP_ENDPOINT is not a valid URI")?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
            anyhow::bail!("OTEL_EXPORTER_OTLP_ENDPOINT must be an http(s) OTLP/gRPC endpoint");
        }
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .context("failed to build configured OTLP trace exporter")?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                Resource::builder()
                    .with_service_name(service_name.to_string())
                    .build(),
            )
            .build();
        let tracer = provider.tracer(service_name.to_string());
        opentelemetry::global::set_tracer_provider(provider.clone());
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .context("failed to initialize tracing subscriber")?;
        Some(provider)
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .try_init()
            .context("failed to initialize tracing subscriber")?;
        None
    };

    OTEL_EXPORT_ENABLED.store(provider.is_some(), Ordering::Relaxed);
    tracing::info!(
        service = service_name,
        otlp = provider.is_some(),
        "tracing initialized"
    );
    Ok(TelemetryGuard { provider })
}

pub async fn serve(app: Router, config: ServiceConfig) -> anyhow::Result<()>
where
    anyhow::Error: From<std::io::Error>,
{
    let app = if OTEL_EXPORT_ENABLED.load(Ordering::Relaxed) {
        app.layer(middleware::from_fn(otel_http_trace))
    } else {
        app.layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
    };
    let listener = TcpListener::bind(config.bind_addr()).await?;
    tracing::info!(
        service = config.service_name,
        addr = %config.bind_addr(),
        "service listening"
    );
    let service: IntoMakeServiceWithConnectInfo<Router, SocketAddr> =
        app.into_make_service_with_connect_info();
    axum::serve(listener, service).await?;
    Ok(())
}

async fn otel_http_trace(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let protocol = format!("{:?}", request.version());
    let parent = TraceContextPropagator::new().extract(&HeaderExtractor(request.headers()));
    let tracer = opentelemetry::global::tracer("asd-core-http");
    let span = tracer
        .span_builder("http.request")
        .with_kind(SpanKind::Server)
        .with_attributes(vec![
            KeyValue::new("http.request.method", method.clone()),
            KeyValue::new("url.path", path.clone()),
            KeyValue::new("network.protocol.version", protocol),
        ])
        .start_with_context(&tracer, &parent);
    let context = OtelContext::new().with_span(span);
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    let span = context.span();
    span.set_attribute(KeyValue::new(
        "http.response.status_code",
        i64::from(status.as_u16()),
    ));
    if status.is_server_error() {
        span.set_status(Status::error(status.to_string()));
    }
    span.end();
    tracing::info!(
        http.request.method = method,
        url.path = path,
        http.response.status_code = status.as_u16(),
        duration_ms = started.elapsed().as_millis(),
        "finished processing request"
    );
    response
}

pub fn env_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

pub fn env_u16(name: &str, default: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub fn env_f64(name: &str, default: f64) -> f64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub fn tenant_key(base: &str) -> String {
    match env::var("TENANT_ID") {
        Ok(tenant) if !tenant.trim().is_empty() => format!("tenant:{tenant}:{base}"),
        _ => base.to_string(),
    }
}

pub fn metrics_text(service: &str, counters: &[(&str, u64)]) -> impl IntoResponse {
    let service = service
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == ':' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let mut body = format!(
        "# HELP {service}_info Service metadata\n# TYPE {service}_info gauge\n{service}_info 1\n"
    );
    for (name, value) in counters {
        body.push_str(&format!("{service}_{name} {value}\n"));
    }
    body
}

pub fn is_blockable_client_ip(candidate: &str) -> bool {
    let Ok(ip) = candidate.parse::<std::net::IpAddr>() else {
        return false;
    };
    !ip_in_configured_ranges(
        ip,
        &[
            "SECURITY_CDN_TRUSTED_PROXY_CIDRS",
            "SECURITY_TRUSTED_PROXY_CIDRS",
        ],
    )
}

fn ip_in_configured_ranges(candidate: std::net::IpAddr, names: &[&str]) -> bool {
    let trusted_ranges = names
        .iter()
        .filter_map(|name| env::var(*name).ok())
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        });
    trusted_ranges
        .into_iter()
        .any(|cidr| ip_in_cidr(candidate, &cidr))
}

fn ip_in_cidr(candidate: std::net::IpAddr, cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return candidate.to_string() == cidr;
    };
    let Ok(network) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match (candidate, network) {
        (std::net::IpAddr::V4(candidate), std::net::IpAddr::V4(network)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(candidate) & mask == u32::from(network) & mask
        }
        (std::net::IpAddr::V6(candidate), std::net::IpAddr::V6(network)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(candidate) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

pub async fn pg_connect_from_env() -> Option<PgClient> {
    if env::var("POSTGRES_ENABLED")
        .map(|value| value.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        return None;
    }
    let host = env_string("PG_HOST", "localhost");
    let port = env_u16("PG_PORT", 5432);
    let db = env_string("PG_DBNAME", "markovdb");
    let user = env_string("PG_USER", "markovuser");
    let password = pg_password().unwrap_or_else(|| env_string("PG_PASSWORD", "markovpass"));
    let mut config = tokio_postgres::Config::new();
    config
        .host(&host)
        .port(port)
        .dbname(&db)
        .user(&user)
        .password(password);
    match config.connect(NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(async move {
                if let Err(exc) = connection.await {
                    tracing::warn!(error = %exc, "PostgreSQL connection task ended");
                }
            });
            Some(client)
        }
        Err(exc) => {
            tracing::warn!(error = %exc, "PostgreSQL unavailable; using fallback behavior");
            None
        }
    }
}

fn pg_password() -> Option<String> {
    if let Ok(path) = env::var("PG_PASSWORD_FILE") {
        if let Ok(value) = std::fs::read_to_string(path) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub event_type: String,
    pub actor: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub enum AuditStore {
    Postgres(Arc<PgClient>),
    Jsonl {
        path: Arc<PathBuf>,
        write_lock: Arc<Mutex<()>>,
    },
    Disabled,
}

impl AuditStore {
    pub async fn from_env(pg: Option<Arc<PgClient>>) -> anyhow::Result<Self> {
        let backend = env_string("AUDIT_STORAGE_BACKEND", "auto").to_ascii_lowercase();
        let store = match backend.as_str() {
            "auto" if pg.is_some() => Self::Postgres(pg.expect("checked above")),
            "auto" | "jsonl" => {
                let path = env_string("AUDIT_JSONL_PATH", "data/security-events.jsonl");
                Self::jsonl(path).await?
            }
            "postgres" | "postgresql" => Self::Postgres(pg.ok_or_else(|| {
                anyhow::anyhow!(
                    "AUDIT_STORAGE_BACKEND=postgres requires an available PostgreSQL connection"
                )
            })?),
            "disabled" | "none" => {
                tracing::warn!("security-event persistence is explicitly disabled");
                Self::Disabled
            }
            _ => anyhow::bail!(
                "AUDIT_STORAGE_BACKEND must be one of: auto, postgres, jsonl, disabled"
            ),
        };
        store.initialize().await?;
        tracing::info!(backend = store.backend_name(), "audit storage initialized");
        Ok(store)
    }

    pub async fn jsonl(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        Ok(Self::Jsonl {
            path: Arc::new(path),
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Postgres(_) => "postgres",
            Self::Jsonl { .. } => "jsonl",
            Self::Disabled => "disabled",
        }
    }

    async fn initialize(&self) -> anyhow::Result<()> {
        if let Self::Postgres(pg) = self {
            ensure_security_event_table(pg).await?;
        }
        Ok(())
    }

    async fn record(
        &self,
        event_type: &str,
        actor: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<()> {
        match self {
            Self::Postgres(pg) => {
                pg.execute(
                    "INSERT INTO security_events (event_type, actor, payload) VALUES ($1, $2, $3)",
                    &[&event_type, &actor, &payload],
                )
                .await?;
            }
            Self::Jsonl { path, write_lock } => {
                let _guard = write_lock.lock().await;
                let event = SecurityEvent {
                    id: Utc::now().timestamp_micros(),
                    event_type: event_type.to_string(),
                    actor: actor.to_string(),
                    payload,
                    created_at: Utc::now(),
                };
                let mut line = serde_json::to_vec(&event)?;
                line.push(b'\n');
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path.as_ref())
                    .await?;
                file.write_all(&line).await?;
                file.flush().await?;
            }
            Self::Disabled => {}
        }
        Ok(())
    }

    async fn load(&self, limit: i64) -> anyhow::Result<Vec<SecurityEvent>> {
        let limit = limit.clamp(1, 10_000);
        match self {
            Self::Postgres(pg) => {
                let rows = pg
                    .query(
                        "SELECT id, event_type, actor, payload, created_at
                         FROM security_events
                         ORDER BY created_at DESC
                         LIMIT $1",
                        &[&limit],
                    )
                    .await?;
                Ok(rows
                    .into_iter()
                    .map(|row| SecurityEvent {
                        id: row.get(0),
                        event_type: row.get(1),
                        actor: row.get(2),
                        payload: row.get(3),
                        created_at: row.get(4),
                    })
                    .collect())
            }
            Self::Jsonl { path, .. } => {
                let contents = tokio::fs::read_to_string(path.as_ref()).await?;
                let mut events = Vec::new();
                for (line_number, line) in contents.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<SecurityEvent>(line) {
                        Ok(event) => events.push(event),
                        Err(exc) => tracing::warn!(
                            error = %exc,
                            line = line_number + 1,
                            path = %path.display(),
                            "skipping malformed audit JSONL record"
                        ),
                    }
                }
                events.sort_by_key(|event| std::cmp::Reverse(event.created_at));
                events.truncate(limit as usize);
                Ok(events)
            }
            Self::Disabled => Ok(Vec::new()),
        }
    }
}

pub async fn ensure_security_event_table(pg: &PgClient) -> Result<(), tokio_postgres::Error> {
    pg.execute(
        "CREATE TABLE IF NOT EXISTS security_events (
            id BIGSERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            payload JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
        &[],
    )
    .await?;
    Ok(())
}

pub async fn record_security_event(
    store: &AuditStore,
    event_type: &str,
    actor: &str,
    payload: serde_json::Value,
) {
    if let Err(exc) = store.record(event_type, actor, payload).await {
        tracing::error!(error = %exc, event_type, actor, "failed to persist security event");
    }
}

pub async fn load_security_events(store: &AuditStore, limit: i64) -> Vec<SecurityEvent> {
    match store.load(limit).await {
        Ok(events) => events,
        Err(exc) => {
            tracing::error!(error = %exc, "failed to load security events");
            Vec::new()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IpAction {
    pub ip: Option<String>,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hs256_jwt_decodes_verified_claims() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"admin","roles":["ops"],"exp":4102444800}"#);
        let signing_input = format!("{header}.{payload}");
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{signing_input}.{signature}");

        let claims = decode_hs256_jwt(&token, "secret").expect("verified claims");

        assert_eq!(claims["sub"], "admin");
        assert!(verify_hs256_jwt(&token, "secret"));
        assert!(decode_hs256_jwt(&token, "wrong").is_none());
    }

    #[test]
    fn cidr_matching_distinguishes_origins_from_proxy_ranges() {
        assert!(ip_in_cidr(
            "173.245.48.10".parse().unwrap(),
            "173.245.48.0/20"
        ));
        assert!(!ip_in_cidr(
            "198.51.100.10".parse().unwrap(),
            "173.245.48.0/20"
        ));
        assert!(ip_in_cidr(
            "2400:cb00::1".parse().unwrap(),
            "2400:cb00::/32"
        ));
    }

    #[test]
    fn tls_attestation_matches_the_cross_runtime_vector() {
        let fingerprint = TlsFingerprint {
            ja3: Some("72a589da586844d7f0818ce684948eea".into()),
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            source: "envoy".into(),
        };
        let token = create_tls_fingerprint_attestation(
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
            "198.51.100.7",
            "GET",
            "/products",
            &fingerprint,
        )
        .unwrap();
        assert_eq!(
            token,
            "v1:1700000000:192976122c9fbaa4cb8c2554be66f2439e020a7d470ac838f2a622b0c5829a49"
        );
        assert!(verify_tls_fingerprint_attestation(
            Some(&token),
            "0123456789abcdef0123456789abcdef",
            60,
            &TlsAttestationContext {
                now: 1_700_000_030,
                client_ip: "198.51.100.7",
                method: "GET",
                path: "/products",
                fingerprint: &fingerprint,
            },
        ));
    }

    #[test]
    fn tls_attestation_rejects_get_root_replay_on_post_admin() {
        let fingerprint = TlsFingerprint {
            ja3: Some("72a589da586844d7f0818ce684948eea".into()),
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            source: "envoy".into(),
        };
        let key = "0123456789abcdef0123456789abcdef";
        let token = create_tls_fingerprint_attestation(
            key,
            1_700_000_000,
            "198.51.100.7",
            "GET",
            "/",
            &fingerprint,
        )
        .unwrap();

        assert!(!verify_tls_fingerprint_attestation(
            Some(&token),
            key,
            60,
            &TlsAttestationContext {
                now: 1_700_000_030,
                client_ip: "198.51.100.7",
                method: "POST",
                path: "/admin",
                fingerprint: &fingerprint,
            },
        ));
    }

    #[test]
    fn tls_attestation_accepts_previous_key_during_rotation() {
        let fingerprint = TlsFingerprint {
            ja3: Some("72a589da586844d7f0818ce684948eea".into()),
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            source: "envoy".into(),
        };
        let current_key = "0123456789abcdef0123456789abcdef";
        let previous_key = "abcdef0123456789abcdef0123456789";
        let token = create_tls_fingerprint_attestation(
            previous_key,
            1_700_000_000,
            "198.51.100.7",
            "GET",
            "/products",
            &fingerprint,
        )
        .unwrap();

        assert!(verify_tls_fingerprint_attestation_with_keys(
            Some(&token),
            &[current_key, previous_key],
            60,
            &TlsAttestationContext {
                now: 1_700_000_030,
                client_ip: "198.51.100.7",
                method: "GET",
                path: "/products",
                fingerprint: &fingerprint,
            },
        ));
    }

    #[test]
    fn w3c_trace_context_extracts_from_http_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01"
                .parse()
                .unwrap(),
        );

        let parent = TraceContextPropagator::new().extract(&HeaderExtractor(&headers));
        let span_context = parent.span().span_context().clone();

        assert!(span_context.is_valid());
        assert_eq!(
            span_context.trace_id().to_string(),
            "11111111111111111111111111111111"
        );
        assert_eq!(span_context.span_id().to_string(), "2222222222222222");
    }

    #[tokio::test]
    async fn jsonl_audit_store_round_trips_events() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "asd-core-audit-{}-{unique}.jsonl",
            std::process::id()
        ));
        let store = AuditStore::jsonl(&path).await.unwrap();

        store
            .record(
                "test_event",
                "test_actor",
                serde_json::json!({"outcome":"recorded"}),
            )
            .await
            .unwrap();
        let events = store.load(10).await.unwrap();

        assert_eq!(store.backend_name(), "jsonl");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "test_event");
        assert_eq!(events[0].payload["outcome"], "recorded");
        tokio::fs::remove_file(path).await.unwrap();
    }
}
