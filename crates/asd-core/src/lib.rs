use axum::{http::HeaderMap, response::IntoResponse, routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet},
    env,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::RwLock};
use tokio_postgres::{Client as PgClient, NoTls};

type HmacSha256 = Hmac<Sha256>;

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
            webhook_shared_secret: env::var("WEBHOOK_SHARED_SECRET").ok(),
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

    pub async fn block(&self, ip: impl Into<String>) {
        let ip = ip.into();
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<usize> = con.sadd(&self.blocklist_key, &ip).await;
                if result.is_ok() {
                    return;
                }
            }
        }
        self.blocked.write().await.insert(ip);
    }

    pub async fn allow(&self, ip: &str) {
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<usize> = con.srem(&self.blocklist_key, ip).await;
                if result.is_ok() {
                    return;
                }
            }
        }
        self.blocked.write().await.remove(ip);
    }

    pub async fn flag(&self, ip: impl Into<String>, reason: impl Into<String>) {
        let ip = ip.into();
        let reason = reason.into();
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<()> = con
                    .set(format!("{}{}", self.flag_prefix, ip), &reason)
                    .await;
                if result.is_ok() {
                    return;
                }
            }
        }
        self.flagged.write().await.insert(ip, reason);
    }

    pub async fn unflag(&self, ip: &str) {
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<usize> =
                    con.del(format!("{}{}", self.flag_prefix, ip)).await;
                if result.is_ok() {
                    return;
                }
            }
        }
        self.flagged.write().await.remove(ip);
    }

    pub async fn contains(&self, ip: &str) -> bool {
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let result: redis::RedisResult<bool> = con.sismember(&self.blocklist_key, ip).await;
                if let Ok(value) = result {
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
                let pattern = format!("{}*", self.flag_prefix);
                let flagged: redis::RedisResult<Vec<String>> = con.keys(pattern).await;
                if let Ok(blocked_count) = blocked_count {
                    return BlocklistStats {
                        blocked_count,
                        flagged_count: flagged.map(|values| values.len()).unwrap_or_default(),
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
    let password = redis_password();
    let url = if let Some(password) = password {
        format!("redis://:{password}@{host}:{port}/{db}")
    } else {
        format!("redis://{host}:{port}/{db}")
    };
    redis::Client::open(url)
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

pub fn is_authorized(headers: &HeaderMap, api_key_env: &str, jwt_secret_env: &str) -> bool {
    let expected_api_key = env::var(api_key_env).ok().filter(|value| !value.is_empty());
    let jwt_secret = env::var(jwt_secret_env)
        .ok()
        .filter(|value| !value.is_empty());
    if expected_api_key.is_none() && jwt_secret.is_none() {
        return true;
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

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .json()
        .try_init();
}

pub async fn serve(app: Router, config: ServiceConfig) -> anyhow::Result<()>
where
    anyhow::Error: From<std::io::Error>,
{
    let listener = TcpListener::bind(config.bind_addr()).await?;
    tracing::info!(
        service = config.service_name,
        addr = %config.bind_addr(),
        "service listening"
    );
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
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
    let mut body = format!(
        "# HELP {service}_info Service metadata\n# TYPE {service}_info gauge\n{service}_info 1\n"
    );
    for (name, value) in counters {
        body.push_str(&format!("{service}_{name} {value}\n"));
    }
    body
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
    let conn_str = format!("host={host} port={port} dbname={db} user={user} password={password}");
    match tokio_postgres::connect(&conn_str, NoTls).await {
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
    pg: Option<&PgClient>,
    event_type: &str,
    actor: &str,
    payload: serde_json::Value,
) {
    let Some(pg) = pg else {
        return;
    };
    if ensure_security_event_table(pg).await.is_err() {
        return;
    }
    let _ = pg
        .execute(
            "INSERT INTO security_events (event_type, actor, payload) VALUES ($1, $2, $3)",
            &[&event_type, &actor, &payload],
        )
        .await;
}

pub async fn load_security_events(pg: Option<&PgClient>, limit: i64) -> Vec<SecurityEvent> {
    let Some(pg) = pg else {
        return Vec::new();
    };
    if ensure_security_event_table(pg).await.is_err() {
        return Vec::new();
    }
    let Ok(rows) = pg
        .query(
            "SELECT id, event_type, actor, payload, created_at
             FROM security_events
             ORDER BY created_at DESC
             LIMIT $1",
            &[&limit],
        )
        .await
    else {
        return Vec::new();
    };
    rows.into_iter()
        .map(|row| SecurityEvent {
            id: row.get(0),
            event_type: row.get(1),
            actor: row.get(2),
            payload: row.get(3),
            created_at: row.get(4),
        })
        .collect()
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
}
