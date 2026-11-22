pub mod gdpr;

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
use hmac::{Hmac, KeyInit, Mac};
use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::{
    SpanKind, Status, TraceContextExt as _, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context as OtelContext, KeyValue};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, Resource};
use redis::{AsyncCommands, IntoConnectionInfo, RedisConnectionInfo};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashMap,
    env,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
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

/// Default block lifetime when `BLOCKLIST_TTL_SECONDS` is not set (24 hours).
pub const DEFAULT_BLOCKLIST_TTL_SECONDS: u64 = 86_400;

/// Blocks are stored one Redis key per address (`blocklist:<ip>`) with an
/// expiry, so a block made in error or against a spoofed address cannot last
/// forever. `BLOCKLIST_TTL_SECONDS=0` disables expiry.
/// What happened to a subject's block during an erasure request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BlockErasure {
    NotBlocked,
    Erased,
    /// Kept under the policy until it expires; `None` means it has no expiry.
    RetainedUntilExpiry {
        seconds_remaining: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SubjectErasure {
    pub block: BlockErasure,
    pub flag_removed: bool,
}

#[derive(Clone)]
pub struct BlocklistState {
    blocked: Arc<RwLock<HashMap<String, Option<Instant>>>>,
    flagged: Arc<RwLock<HashMap<String, String>>>,
    redis: Option<redis::Client>,
    blocklist_key: String,
    flag_prefix: String,
    block_ttl: Option<Duration>,
}

impl Default for BlocklistState {
    fn default() -> Self {
        Self {
            blocked: Arc::default(),
            flagged: Arc::default(),
            redis: None,
            blocklist_key: String::new(),
            flag_prefix: String::new(),
            block_ttl: block_ttl_from_seconds(DEFAULT_BLOCKLIST_TTL_SECONDS),
        }
    }
}

fn block_ttl_from_seconds(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

fn block_is_live(expiry: &Option<Instant>) -> bool {
    expiry.is_none_or(|at| at > Instant::now())
}

impl BlocklistState {
    pub async fn from_env() -> anyhow::Result<Self> {
        let mut state = Self {
            blocklist_key: tenant_key("blocklist"),
            flag_prefix: tenant_key("ip_flag:"),
            block_ttl: block_ttl_from_seconds(env_u64(
                "BLOCKLIST_TTL_SECONDS",
                DEFAULT_BLOCKLIST_TTL_SECONDS,
            )),
            ..Self::default()
        };
        if env::var("REDIS_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("false"))
            .unwrap_or(false)
        {
            return Ok(state);
        }

        match redis_client_from_env("REDIS_DB_BLOCKLIST", 0) {
            Ok(client) => match client.get_multiplexed_async_connection().await {
                Ok(mut con) => {
                    let ping: redis::RedisResult<String> =
                        redis::cmd("PING").query_async(&mut con).await;
                    if ping.is_ok() {
                        state.migrate_legacy_blocklist(&mut con).await?;
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
        Ok(state)
    }

    fn block_key(&self, ip: &str) -> String {
        format!("{}:{ip}", self.blocklist_key)
    }

    async fn write_block(
        con: &mut redis::aio::MultiplexedConnection,
        key: &str,
        reason: &str,
        ttl: Option<Duration>,
    ) -> redis::RedisResult<()> {
        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(reason);
        if let Some(ttl) = ttl {
            cmd.arg("EX").arg(ttl.as_secs());
        }
        cmd.query_async(con).await
    }

    /// Earlier releases kept blocks in one Redis set with no expiry. Move each
    /// valid entry to its own expiring key and remove it from the set.
    async fn migrate_legacy_blocklist(
        &self,
        con: &mut redis::aio::MultiplexedConnection,
    ) -> anyhow::Result<()> {
        let entries: Vec<String> = con.smembers(&self.blocklist_key).await?;
        let (migrations, invalid) = blocklist_migration_plan(entries);
        for ip in invalid {
            tracing::warn!(ip = %ip, "invalid persisted blocklist entry left unchanged");
        }
        let mut migrated = 0usize;
        for (legacy, canonical) in migrations {
            let mut pipe = redis::pipe();
            pipe.atomic()
                .cmd("SET")
                .arg(self.block_key(&canonical))
                .arg("blocked");
            if let Some(ttl) = self.block_ttl {
                pipe.arg("EX").arg(ttl.as_secs());
            }
            pipe.arg("NX")
                .ignore()
                .cmd("SREM")
                .arg(&self.blocklist_key)
                .arg(&legacy)
                .ignore();
            pipe.query_async::<()>(con).await?;
            migrated += 1;
        }
        if migrated > 0 {
            tracing::info!(
                migrated,
                "moved legacy blocklist set entries to expiring per-address keys"
            );
        }
        Ok(())
    }

    pub async fn block(&self, ip: impl Into<String>) -> bool {
        self.block_with_reason(ip, "blocked").await
    }

    /// Block an address and store why (the Redis value, as in the Python
    /// edition). A repeat block refreshes the expiry.
    pub async fn block_with_reason(&self, ip: impl Into<String>, reason: &str) -> bool {
        let reason: String = reason.trim().chars().take(256).collect();
        let reason = if reason.is_empty() {
            "blocked".to_string()
        } else {
            reason
        };
        let ip = ip.into();
        if !is_blockable_client_ip(&ip) {
            tracing::warn!(ip = %ip, "refusing to block an invalid or trusted infrastructure IP");
            return false;
        }
        let ip = normalize_client_ip(&ip).expect("validated IP address");
        let expiry = self.block_ttl.map(|ttl| Instant::now() + ttl);
        self.blocked.write().await.insert(ip.clone(), expiry);
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                if let Err(exc) =
                    Self::write_block(&mut con, &self.block_key(&ip), &reason, self.block_ttl).await
                {
                    tracing::warn!(error = %exc, ip = %ip, "failed to persist block to Redis; in-memory block remains active");
                }
            }
        }
        true
    }

    pub async fn allow(&self, ip: &str) {
        let Some(ip) = normalize_client_ip(ip) else {
            return;
        };
        self.blocked.write().await.remove(&ip);
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<usize> = con.del(self.block_key(&ip)).await;
                if let Err(exc) = result {
                    tracing::warn!(error = %exc, ip, "failed to remove block from Redis; in-memory block was removed");
                }
            }
        }
    }

    pub async fn flag(&self, ip: impl Into<String>, reason: impl Into<String>) -> bool {
        let ip = ip.into();
        let Some(ip) = normalize_client_ip(&ip) else {
            tracing::warn!(ip = %ip, "refusing to flag an invalid IP");
            return false;
        };
        let reason = reason.into();
        if reason.trim().is_empty() || reason.len() > 256 {
            tracing::warn!(ip = %ip, "refusing to flag IP with invalid reason length");
            return false;
        }
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
        true
    }

    /// Erases what this service holds about one address for a data-subject request: the flag always, and the block
    /// according to `policy` (kept until it expires, or removed now). Reports what happened to each.
    pub async fn erase_subject(&self, ip: &str, policy: gdpr::ActiveBlockPolicy) -> SubjectErasure {
        let Some(ip) = normalize_client_ip(ip) else {
            return SubjectErasure {
                block: BlockErasure::NotBlocked,
                flag_removed: false,
            };
        };
        let flag_removed = self.flagged.read().await.contains_key(&ip);
        self.unflag(&ip).await;

        // Redis is authoritative whenever it answers; the in-memory map only serves while it is unreachable.
        let mut remaining: Option<Option<u64>> = None; // Some(None) = blocked without an expiry
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let ttl: redis::RedisResult<i64> = redis::cmd("TTL")
                    .arg(self.block_key(&ip))
                    .query_async(&mut con)
                    .await;
                match ttl {
                    Ok(-2) => remaining = None,
                    Ok(-1) => remaining = Some(None),
                    Ok(seconds) => remaining = Some(Some(seconds as u64)),
                    Err(_) => {}
                }
            }
        }
        if remaining.is_none() {
            let now = Instant::now();
            if let Some(expiry) = self.blocked.read().await.get(&ip) {
                if block_is_live(expiry) {
                    remaining = Some(expiry.map(|at| at.saturating_duration_since(now).as_secs()));
                }
            }
        }

        let block = match (remaining, policy) {
            (None, _) => BlockErasure::NotBlocked,
            (Some(_), gdpr::ActiveBlockPolicy::EraseNow) => {
                self.allow(&ip).await;
                BlockErasure::Erased
            }
            (Some(seconds), gdpr::ActiveBlockPolicy::RetainUntilExpiry) => {
                BlockErasure::RetainedUntilExpiry {
                    seconds_remaining: seconds,
                }
            }
        };
        SubjectErasure {
            block,
            flag_removed,
        }
    }

    pub async fn unflag(&self, ip: &str) {
        let Some(ip) = normalize_client_ip(ip) else {
            return;
        };
        self.flagged.write().await.remove(&ip);
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

    /// Redis is authoritative whenever it answers, so a block that expired or
    /// was removed by another service is never revived from this process's
    /// memory. The in-memory copy only serves while Redis is unreachable.
    pub async fn contains(&self, ip: &str) -> bool {
        let Some(ip) = normalize_client_ip(ip) else {
            return false;
        };
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let remaining_ms: redis::RedisResult<i64> = redis::cmd("PTTL")
                    .arg(self.block_key(&ip))
                    .query_async(&mut con)
                    .await;
                match remaining_ms {
                    Ok(-2) => {
                        self.blocked.write().await.remove(&ip);
                        return false;
                    }
                    Ok(ms) => {
                        let expiry = u64::try_from(ms)
                            .ok()
                            .map(|ms| Instant::now() + Duration::from_millis(ms));
                        self.blocked.write().await.insert(ip, expiry);
                        return true;
                    }
                    Err(_) => {}
                }
            }
        }
        let remembered = self.blocked.read().await.get(&ip).copied();
        match remembered {
            Some(expiry) if block_is_live(&expiry) => true,
            Some(_) => {
                self.blocked.write().await.remove(&ip);
                false
            }
            None => false,
        }
    }

    async fn redis_blocked(&self) -> Option<Vec<String>> {
        let client = self.redis.as_ref()?;
        let mut con = client.get_multiplexed_async_connection().await.ok()?;
        let prefix = format!("{}:", self.blocklist_key);
        let mut entries = Vec::new();
        let mut scan = con
            .scan_match::<_, String>(format!("{prefix}*"))
            .await
            .ok()?;
        while let Some(Ok(key)) = scan.next_item().await {
            if let Some(ip) = key.strip_prefix(&prefix) {
                entries.push(ip.to_string());
            }
        }
        entries.sort();
        Some(entries)
    }

    async fn memory_blocked(&self) -> Vec<String> {
        let mut blocked = self.blocked.write().await;
        blocked.retain(|_, expiry| block_is_live(expiry));
        let mut entries = blocked.keys().cloned().collect::<Vec<_>>();
        entries.sort();
        entries
    }

    pub async fn blocked(&self) -> Vec<String> {
        match self.redis_blocked().await {
            Some(entries) => entries,
            None => self.memory_blocked().await,
        }
    }

    pub async fn stats(&self) -> BlocklistStats {
        if let Some(client) = &self.redis {
            if let Some(blocked) = self.redis_blocked().await {
                if let Ok(mut con) = client.get_multiplexed_async_connection().await {
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
                        blocked_count: blocked.len(),
                        flagged_count,
                    };
                }
            }
        }
        BlocklistStats {
            blocked_count: self.memory_blocked().await.len(),
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
    let mut redis_settings = RedisConnectionInfo::default().set_db(i64::from(db));
    if let Some(username) = env::var("REDIS_USERNAME")
        .ok()
        .filter(|value| !value.is_empty())
    {
        redis_settings = redis_settings.set_username(username);
    }
    if let Some(password) = redis_password() {
        redis_settings = redis_settings.set_password(password);
    }

    let connection_info = (host, port)
        .into_connection_info()?
        .set_redis_settings(redis_settings);
    redis::Client::open(connection_info)
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

pub fn hmac_sha256_hex(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts arbitrary key lengths");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
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
        if has_valid_api_key(headers, &expected) {
            return true;
        }
    }

    if let Some(secret) = jwt_secret {
        let token = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let Some(claims) = decode_hs256_jwt(token, &secret) else {
            return false;
        };
        let scope_name = format!(
            "{}_JWT_SCOPE",
            api_key_env.strip_suffix("_API_KEY").unwrap_or(api_key_env)
        );
        let required_scope = env::var(&scope_name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                api_key_env
                    .strip_suffix("_API_KEY")
                    .unwrap_or(api_key_env)
                    .to_ascii_lowercase()
            });
        return jwt_has_scope(&claims, &required_scope);
    }

    false
}

pub fn has_valid_api_key(headers: &HeaderMap, expected: &str) -> bool {
    let Some(provided) = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    constant_time_eq(expected.as_bytes(), provided.as_bytes())
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

    let header_bytes = URL_SAFE_NO_PAD.decode(header).ok()?;
    let header_json = serde_json::from_slice::<serde_json::Value>(&header_bytes).ok()?;
    if header_json.get("alg").and_then(|value| value.as_str()) != Some("HS256") {
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
    let now = Utc::now().timestamp();
    let leeway = env_u64("JWT_CLOCK_SKEW_SECONDS", 60) as i64;
    let exp = payload_json.get("exp")?.as_i64()?;
    let iat = payload_json.get("iat")?.as_i64()?;
    if now.saturating_sub(leeway) >= exp || iat > now.saturating_add(leeway) {
        return None;
    }
    if payload_json
        .get("nbf")
        .and_then(|value| value.as_i64())
        .is_some_and(|nbf| nbf > now.saturating_add(leeway))
    {
        return None;
    }
    let issuer = env::var("JWT_ISSUER").ok();
    let audience = env::var("JWT_AUDIENCE").ok();
    if !jwt_claims_match_config(&payload_json, issuer.as_deref(), audience.as_deref()) {
        return None;
    }
    Some(payload_json)
}

fn jwt_claims_match_config(
    claims: &serde_json::Value,
    issuer: Option<&str>,
    audience: Option<&str>,
) -> bool {
    issuer
        .filter(|value| !value.trim().is_empty())
        .is_none_or(|expected| claims.get("iss").and_then(|value| value.as_str()) == Some(expected))
        && audience
            .filter(|value| !value.trim().is_empty())
            .is_none_or(|expected| jwt_audience_matches(claims, expected))
}

fn jwt_audience_matches(claims: &serde_json::Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(serde_json::Value::String(value)) => value == expected,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

fn jwt_has_scope(claims: &serde_json::Value, required: &str) -> bool {
    let claim = claims.get("scope").or_else(|| claims.get("scp"));
    match claim {
        Some(serde_json::Value::String(scopes)) => {
            scopes.split_whitespace().any(|scope| scope == required)
        }
        Some(serde_json::Value::Array(scopes)) => {
            scopes.iter().any(|scope| scope.as_str() == Some(required))
        }
        _ => false,
    }
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
    let Some(normalized) = normalize_client_ip(candidate) else {
        return false;
    };
    let ip = normalized
        .parse::<std::net::IpAddr>()
        .expect("normalized IP");
    !ip_in_configured_ranges(
        ip,
        &[
            "SECURITY_CDN_TRUSTED_PROXY_CIDRS",
            "SECURITY_TRUSTED_PROXY_CIDRS",
        ],
    )
}

/// The canonical form of an address, or `None` when it is not a valid IP.
pub fn normalize_subject_ip(candidate: &str) -> Option<String> {
    normalize_client_ip(candidate)
}

fn normalize_client_ip(candidate: &str) -> Option<String> {
    let ip = candidate.parse::<std::net::IpAddr>().ok()?;
    Some(canonical_ip_addr(ip).to_string())
}

fn blocklist_migration_plan(entries: Vec<String>) -> (Vec<(String, String)>, Vec<String>) {
    let mut migrations = Vec::new();
    let mut invalid = Vec::new();
    for legacy in entries {
        match normalize_client_ip(&legacy) {
            Some(canonical) => migrations.push((legacy, canonical)),
            None => invalid.push(legacy),
        }
    }
    (migrations, invalid)
}

fn canonical_ip_addr(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(ip)),
        ip => ip,
    }
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
    let candidate = canonical_ip_addr(candidate);
    let Some((address, prefix)) = cidr.split_once('/') else {
        return cidr
            .parse::<std::net::IpAddr>()
            .map(|network| candidate == canonical_ip_addr(network))
            .unwrap_or(false);
    };
    let Ok(mut network) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(mut prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if let (std::net::IpAddr::V4(_), std::net::IpAddr::V6(v6)) = (candidate, network) {
        if let Some(mapped) = v6.to_ipv4_mapped() {
            network = std::net::IpAddr::V4(mapped);
            prefix = prefix.saturating_sub(96);
        }
    }
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
    let Some(password) = pg_password().or_else(|| {
        env::var("PG_PASSWORD")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }) else {
        tracing::error!(
            "PostgreSQL is enabled but PG_PASSWORD/PG_PASSWORD_FILE is not configured; run scripts/configure_credentials.py"
        );
        return None;
    };
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

    /// Redacts or removes every stored event that mentions `ip` as a whole address, and returns how many events changed.
    pub async fn erase_subject_events(
        &self,
        ip: &str,
        mode: gdpr::ErasureMode,
    ) -> anyhow::Result<u64> {
        if mode == gdpr::ErasureMode::Manual {
            return Ok(0);
        }
        match self {
            Self::Postgres(pg) => {
                let rows = pg
                    .query(
                        "SELECT id, payload FROM security_events WHERE position($1 in payload::text) > 0",
                        &[&ip],
                    )
                    .await?;
                let mut changed = 0;
                for row in rows {
                    let id: i64 = row.get(0);
                    let mut payload: serde_json::Value = row.get(1);
                    if !gdpr::mentions_subject(&payload, ip) {
                        continue;
                    }
                    match mode {
                        gdpr::ErasureMode::Delete => {
                            pg.execute("DELETE FROM security_events WHERE id = $1", &[&id])
                                .await?;
                        }
                        _ => {
                            gdpr::redact_subject(&mut payload, ip);
                            pg.execute(
                                "UPDATE security_events SET payload = $1 WHERE id = $2",
                                &[&payload, &id],
                            )
                            .await?;
                        }
                    }
                    changed += 1;
                }
                Ok(changed)
            }
            Self::Jsonl { path, write_lock } => {
                let _guard = write_lock.lock().await;
                let contents = tokio::fs::read_to_string(path.as_ref()).await?;
                let mut output = String::with_capacity(contents.len());
                let mut changed = 0;
                for line in contents.lines() {
                    match serde_json::from_str::<SecurityEvent>(line) {
                        Ok(mut event) if gdpr::mentions_subject(&event.payload, ip) => {
                            changed += 1;
                            if mode == gdpr::ErasureMode::Delete {
                                continue;
                            }
                            gdpr::redact_subject(&mut event.payload, ip);
                            output.push_str(&serde_json::to_string(&event)?);
                            output.push('\n');
                        }
                        // everything else, including a malformed or blank line, is written back untouched
                        _ => {
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
                if changed > 0 {
                    let temporary = path.with_extension("jsonl.erasing");
                    tokio::fs::write(&temporary, output).await?;
                    tokio::fs::rename(&temporary, path.as_ref()).await?;
                }
                Ok(changed)
            }
            Self::Disabled => Ok(0),
        }
    }

    /// How many security events are stored, for the compliance report.
    pub async fn count_events(&self) -> anyhow::Result<u64> {
        match self {
            Self::Postgres(pg) => {
                let row = pg
                    .query_one("SELECT count(*) FROM security_events", &[])
                    .await?;
                Ok(row.get::<_, i64>(0) as u64)
            }
            Self::Jsonl { path, .. } => {
                let contents = tokio::fs::read_to_string(path.as_ref()).await?;
                Ok(contents
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count() as u64)
            }
            Self::Disabled => Ok(0),
        }
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

    async fn temp_audit_store() -> (AuditStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("asd-gdpr-{}.jsonl", uuid::Uuid::new_v4()));
        (AuditStore::jsonl(&path).await.unwrap(), path)
    }

    #[tokio::test]
    async fn jsonl_erasure_redacts_only_whole_address_matches_and_keeps_everything_else() {
        let (store, path) = temp_audit_store().await;
        record_security_event(
            &store,
            "admin_block_ip",
            "admin",
            serde_json::json!({"ip": "203.0.113.7", "reason": "scraper"}),
        )
        .await;
        record_security_event(
            &store,
            "tarpit_hit",
            "system",
            serde_json::json!({"client": "seen 203.0.113.7 twice", "path": "/x"}),
        )
        .await;
        record_security_event(
            &store,
            "tarpit_hit",
            "system",
            serde_json::json!({"client": "203.0.113.70"}),
        )
        .await;
        record_security_event(
            &store,
            "admin_unblock_ip",
            "admin",
            serde_json::json!({"ip": "198.51.100.1"}),
        )
        .await;
        // a malformed line must survive untouched
        let mut contents = tokio::fs::read_to_string(&path).await.unwrap();
        contents.push_str("not json at all\n");
        tokio::fs::write(&path, contents).await.unwrap();

        let changed = store
            .erase_subject_events("203.0.113.7", gdpr::ErasureMode::Redact)
            .await
            .unwrap();

        assert_eq!(changed, 2);
        let raw = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(!raw.contains("\"203.0.113.7\""));
        assert!(!raw.contains("seen 203.0.113.7"));
        assert!(raw.contains("[erased]"));
        assert!(
            raw.contains("203.0.113.70"),
            "a longer address must be left alone"
        );
        assert!(raw.contains("198.51.100.1"));
        assert!(raw.contains("not json at all"));
        let events = load_security_events(&store, 100).await;
        assert_eq!(events.len(), 4, "redaction keeps every event");
        assert!(events
            .iter()
            .any(|event| event.event_type == "admin_block_ip"
                && event.payload["ip"] == "[erased]"
                && event.payload["reason"] == "scraper"));
        assert!(
            !path.with_extension("jsonl.erasing").exists(),
            "the temporary file is renamed away"
        );
        assert_eq!(
            store
                .erase_subject_events("203.0.113.7", gdpr::ErasureMode::Redact)
                .await
                .unwrap(),
            0,
            "idempotent"
        );
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn jsonl_deletion_removes_matching_events_and_manual_mode_touches_nothing() {
        let (store, path) = temp_audit_store().await;
        record_security_event(
            &store,
            "a",
            "admin",
            serde_json::json!({"ip": "203.0.113.7"}),
        )
        .await;
        record_security_event(
            &store,
            "b",
            "admin",
            serde_json::json!({"ip": "203.0.113.8"}),
        )
        .await;

        assert_eq!(
            store
                .erase_subject_events("203.0.113.7", gdpr::ErasureMode::Manual)
                .await
                .unwrap(),
            0
        );
        assert_eq!(store.count_events().await.unwrap(), 2);

        assert_eq!(
            store
                .erase_subject_events("203.0.113.7", gdpr::ErasureMode::Delete)
                .await
                .unwrap(),
            1
        );
        let remaining = load_security_events(&store, 10).await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].payload["ip"], "203.0.113.8");
        assert_eq!(store.count_events().await.unwrap(), 1);
        let _ = tokio::fs::remove_file(&path).await;
        assert_eq!(
            AuditStore::Disabled
                .erase_subject_events("203.0.113.7", gdpr::ErasureMode::Redact)
                .await
                .unwrap(),
            0
        );
        assert_eq!(AuditStore::Disabled.count_events().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn an_active_block_is_kept_until_expiry_or_erased_now_according_to_the_policy() {
        let state = BlocklistState::default();
        assert!(state.block_with_reason("203.0.113.7", "scraper").await);
        assert!(state.flag("203.0.113.7", "suspicious").await);

        let kept = state
            .erase_subject("203.0.113.7", gdpr::ActiveBlockPolicy::RetainUntilExpiry)
            .await;

        assert!(kept.flag_removed, "the flag is always erased");
        match kept.block {
            BlockErasure::RetainedUntilExpiry {
                seconds_remaining: Some(seconds),
            } => {
                assert!(
                    seconds > 80_000 && seconds <= DEFAULT_BLOCKLIST_TTL_SECONDS,
                    "{seconds}"
                );
            }
            other => panic!("expected a retained block with an expiry, got {other:?}"),
        }
        assert!(state.contains("203.0.113.7").await);

        let erased = state
            .erase_subject("203.0.113.7", gdpr::ActiveBlockPolicy::EraseNow)
            .await;

        assert_eq!(erased.block, BlockErasure::Erased);
        assert!(!erased.flag_removed, "the flag was already gone");
        assert!(!state.contains("203.0.113.7").await);
    }

    #[tokio::test]
    async fn erasing_an_unknown_or_invalid_subject_reports_nothing_to_erase() {
        let state = BlocklistState::default();
        let unknown = state
            .erase_subject("203.0.113.9", gdpr::ActiveBlockPolicy::EraseNow)
            .await;
        assert_eq!(
            unknown,
            SubjectErasure {
                block: BlockErasure::NotBlocked,
                flag_removed: false
            }
        );
        let invalid = state
            .erase_subject("not an ip", gdpr::ActiveBlockPolicy::EraseNow)
            .await;
        assert_eq!(invalid.block, BlockErasure::NotBlocked);
        assert_eq!(
            normalize_subject_ip("2001:0db8:0:0:0:0:0:1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(normalize_subject_ip("nope"), None);
    }

    #[tokio::test]
    async fn a_block_without_an_expiry_is_reported_as_such() {
        let state = BlocklistState {
            block_ttl: None,
            ..BlocklistState::default()
        };
        assert!(state.block_with_reason("203.0.113.7", "permanent").await);

        let report = state
            .erase_subject("203.0.113.7", gdpr::ActiveBlockPolicy::RetainUntilExpiry)
            .await;

        assert_eq!(
            report.block,
            BlockErasure::RetainedUntilExpiry {
                seconds_remaining: None
            }
        );
    }

    #[tokio::test]
    async fn blocklist_uses_canonical_ip_addresses() {
        let state = BlocklistState::default();
        assert!(state.block("2001:0db8:0000:0000::1").await);
        assert!(state.contains("2001:db8::1").await);
        assert_eq!(state.blocked().await, vec!["2001:db8::1"]);
        state.allow("2001:0db8::1").await;
        assert!(!state.contains("2001:db8::1").await);

        assert!(state.block("::ffff:198.51.100.7").await);
        assert!(state.contains("198.51.100.7").await);
        state.allow("198.51.100.7").await;
        assert!(!state.contains("::ffff:198.51.100.7").await);

        assert!(state.flag("2001:0db8::1", "probe").await);
        assert_eq!(
            state.flagged.read().await.get("2001:db8::1"),
            Some(&"probe".to_string())
        );
        state.unflag("2001:db8::1").await;
        assert!(state.flagged.read().await.is_empty());
        assert!(!state.flag("not-an-ip", "probe").await);
        assert!(!state.flag("198.51.100.7", " ").await);
        assert!(!state.flag("198.51.100.7", "x".repeat(257)).await);
        assert!(state.flagged.read().await.is_empty());
    }

    #[tokio::test]
    async fn blocks_expire_after_the_configured_lifetime() {
        let state = BlocklistState {
            block_ttl: Some(Duration::from_millis(40)),
            ..BlocklistState::default()
        };
        assert!(state.block("198.51.100.20").await);
        assert!(state.contains("198.51.100.20").await);
        assert_eq!(state.stats().await.blocked_count, 1);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(!state.contains("198.51.100.20").await);
        assert!(state.blocked().await.is_empty());
        assert_eq!(state.stats().await.blocked_count, 0);
    }

    #[tokio::test]
    async fn zero_lifetime_means_blocks_never_expire() {
        assert_eq!(block_ttl_from_seconds(0), None);
        let state = BlocklistState {
            block_ttl: block_ttl_from_seconds(0),
            ..BlocklistState::default()
        };
        assert!(state.block("198.51.100.21").await);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(state.contains("198.51.100.21").await);
    }

    #[test]
    fn default_block_lifetime_is_twenty_four_hours() {
        assert_eq!(
            BlocklistState::default().block_ttl,
            Some(Duration::from_secs(86_400))
        );
    }

    #[test]
    fn mapped_trusted_cidrs_keep_their_ipv4_scope() {
        let mapped = "::ffff:10.2.0.0/112";
        assert!(ip_in_cidr("10.2.3.4".parse().unwrap(), mapped));
        assert!(ip_in_cidr("::ffff:10.2.3.4".parse().unwrap(), mapped));
        assert!(!ip_in_cidr("10.3.3.4".parse().unwrap(), mapped));
        assert!(ip_in_cidr("10.2.3.4".parse().unwrap(), "::ffff:10.2.3.4"));
        assert!(ip_in_cidr(
            "192.0.2.1".parse().unwrap(),
            "::ffff:0.0.0.0/96"
        ));
    }

    #[test]
    fn legacy_blocklist_entries_are_planned_for_migration() {
        let (migrations, invalid) = blocklist_migration_plan(vec![
            "2001:0db8::1".into(),
            "::ffff:198.51.100.7".into(),
            "2001:db8::2".into(),
            "not-an-ip".into(),
        ]);
        assert_eq!(
            migrations,
            vec![
                ("2001:0db8::1".into(), "2001:db8::1".into()),
                ("::ffff:198.51.100.7".into(), "198.51.100.7".into()),
                ("2001:db8::2".into(), "2001:db8::2".into())
            ]
        );
        assert_eq!(invalid, vec!["not-an-ip"]);
    }

    #[test]
    fn hs256_jwt_decodes_verified_claims() {
        let secret = uuid::Uuid::new_v4().to_string();
        let wrong_secret = uuid::Uuid::new_v4().to_string();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD
            .encode(r#"{"sub":"admin","roles":["ops"],"iat":1700000000,"exp":4102444800}"#);
        let signing_input = format!("{header}.{payload}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{signing_input}.{signature}");

        let claims = decode_hs256_jwt(&token, &secret).expect("verified claims");

        assert_eq!(claims["sub"], "admin");
        assert!(verify_hs256_jwt(&token, &secret));
        assert!(decode_hs256_jwt(&token, &wrong_secret).is_none());
    }

    #[test]
    fn jwt_scope_issuer_and_audience_are_checked() {
        let claims = serde_json::json!({
            "scope": "cloud_proxy metrics:read",
            "iss": "trusted-issuer",
            "aud": ["other-service", "cloud-proxy"]
        });
        assert!(jwt_has_scope(&claims, "cloud_proxy"));
        assert!(!jwt_has_scope(&claims, "admin"));
        assert!(jwt_has_scope(
            &serde_json::json!({"scp": ["admin"]}),
            "admin"
        ));
        assert!(jwt_claims_match_config(
            &claims,
            Some("trusted-issuer"),
            Some("cloud-proxy")
        ));
        assert!(!jwt_claims_match_config(
            &claims,
            Some("other-issuer"),
            Some("cloud-proxy")
        ));
        assert!(!jwt_claims_match_config(
            &claims,
            Some("trusted-issuer"),
            Some("other-audience")
        ));
        assert!(jwt_claims_match_config(&claims, None, None));
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
