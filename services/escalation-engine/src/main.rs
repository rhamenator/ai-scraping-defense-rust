use asd_core::{
    env_string, env_u64, health, is_authorized, load_security_events, metrics_text,
    observability_router, pg_connect_from_env, record_security_event, redis_client_from_env, serve,
    tenant_key, BlocklistState, ServiceConfig,
};
use asd_detection::{decide, FrequencyFeatures, InMemoryFrequency, RequestMetadata};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::json;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct FrequencyStore {
    memory: InMemoryFrequency,
    redis: Option<redis::Client>,
    key_prefix: String,
    window: Duration,
    ttl_seconds: usize,
}

impl FrequencyStore {
    async fn from_env() -> Self {
        let window_seconds = env_u64("FREQUENCY_WINDOW_SECONDS", 300);
        let mut store = Self {
            memory: InMemoryFrequency::default(),
            redis: None,
            key_prefix: env_string("FREQUENCY_KEY_PREFIX", &tenant_key("freq:")),
            window: Duration::from_secs(window_seconds),
            ttl_seconds: (window_seconds + 60) as usize,
        };
        if let Ok(client) = redis_client_from_env("REDIS_DB_FREQUENCY", 0) {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let ping: redis::RedisResult<String> =
                    redis::cmd("PING").query_async(&mut con).await;
                if ping.is_ok() {
                    tracing::info!("connected to Redis-backed frequency store");
                    store.redis = Some(client);
                }
            }
        }
        store
    }

    async fn record(&self, ip: &str) -> FrequencyFeatures {
        if let Some(client) = &self.redis {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let now = unix_seconds();
                let window_start = now - self.window.as_secs_f64();
                let key = format!("{}{ip}", self.key_prefix);
                let now_member = format!("{now:.6}");
                let remove_result: redis::RedisResult<i32> = redis::cmd("ZREMRANGEBYSCORE")
                    .arg(&key)
                    .arg("-inf")
                    .arg(format!("({window_start}"))
                    .query_async(&mut con)
                    .await;
                if remove_result.is_ok() {
                    let _: redis::RedisResult<i32> = redis::cmd("ZADD")
                        .arg(&key)
                        .arg(now)
                        .arg(&now_member)
                        .query_async(&mut con)
                        .await;
                    let count: redis::RedisResult<u64> = redis::cmd("ZCOUNT")
                        .arg(&key)
                        .arg(window_start)
                        .arg(now)
                        .query_async(&mut con)
                        .await;
                    let entries: redis::RedisResult<Vec<(String, f64)>> = redis::cmd("ZRANGE")
                        .arg(&key)
                        .arg(-2)
                        .arg(-1)
                        .arg("WITHSCORES")
                        .query_async(&mut con)
                        .await;
                    let _: redis::RedisResult<bool> = redis::cmd("EXPIRE")
                        .arg(&key)
                        .arg(self.ttl_seconds)
                        .query_async(&mut con)
                        .await;
                    if let Ok(count) = count {
                        let time_since = entries
                            .ok()
                            .and_then(|entries| {
                                entries.iter().rev().nth(1).map(|(_, score)| now - score)
                            })
                            .map(|value| (value * 1000.0).round() / 1000.0)
                            .unwrap_or(-1.0);
                        return FrequencyFeatures {
                            count: count.saturating_sub(1),
                            time_since,
                        };
                    }
                }
            }
        }
        self.memory.record(ip, self.window).await
    }
}

fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}

#[derive(Clone)]
struct AppState {
    config: ServiceConfig,
    frequency: FrequencyStore,
    blocklist: BlocklistState,
    pg: Option<Arc<tokio_postgres::Client>>,
    requests: Arc<AtomicU64>,
    bots: Arc<AtomicU64>,
}

#[derive(Serialize)]
struct EscalationResponse {
    status: &'static str,
    is_bot: bool,
    score: f64,
    action: String,
    reason: String,
    fingerprint: String,
    features: serde_json::Value,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("escalation-engine", 8002);
    let state = AppState {
        config: config.clone(),
        frequency: FrequencyStore::from_env().await,
        blocklist: BlocklistState::from_env().await,
        pg: pg_connect_from_env().await.map(Arc::new),
        requests: Arc::new(AtomicU64::new(0)),
        bots: Arc::new(AtomicU64::new(0)),
    };
    let app = Router::new()
        .route(
            "/health",
            get(|| async { health("escalation-engine").await }),
        )
        .route("/escalate", post(escalate))
        .route("/metrics", get(metrics))
        .route("/security-events", get(security_events))
        .route("/admin/reload_plugins", post(reload_plugins))
        .merge(observability_router("escalation-engine"))
        .with_state(state);
    serve(app, config).await
}

async fn escalate(
    State(state): State<AppState>,
    Json(metadata): Json<RequestMetadata>,
) -> Json<EscalationResponse> {
    state.requests.fetch_add(1, Ordering::Relaxed);
    let ip = metadata.ip.clone().unwrap_or_else(|| "unknown".to_string());
    let freq = state.frequency.record(&ip).await;
    let decision = decide(
        metadata,
        freq,
        state.config.throttle_threshold,
        state.config.tarpit_threshold,
        state.config.block_threshold,
    );
    if decision.is_bot {
        state.bots.fetch_add(1, Ordering::Relaxed);
    }
    if decision.action == "block_ip" && ip != "unknown" {
        state.blocklist.block(ip.clone()).await;
    }
    record_security_event(
        state.pg.as_deref(),
        "escalation_decision",
        &ip,
        json!({
            "is_bot": decision.is_bot,
            "score": decision.score,
            "action": decision.action,
            "reason": decision.reason,
            "fingerprint": decision.fingerprint
        }),
    )
    .await;
    Json(EscalationResponse {
        status: "success",
        is_bot: decision.is_bot,
        score: decision.score,
        action: decision.action,
        reason: decision.reason,
        fingerprint: decision.fingerprint,
        features: serde_json::to_value(decision.features).unwrap_or_else(|_| json!({})),
    })
}

async fn metrics(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    metrics_text(
        "escalation_engine",
        &[
            ("requests_total", state.requests.load(Ordering::Relaxed)),
            ("bots_detected_total", state.bots.load(Ordering::Relaxed)),
        ],
    )
}

async fn security_events(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"events": load_security_events(state.pg.as_deref(), 100).await}))
}

async fn reload_plugins(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ESCALATION_API_KEY", "JWT_SECRET") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status":"error","message":"Unauthorized"})),
        ));
    }
    record_security_event(
        state.pg.as_deref(),
        "admin_reload_plugins",
        "admin",
        json!({"service":"escalation-engine"}),
    )
    .await;
    Ok(Json(json!({
        "status": "success",
        "loaded_plugins": [],
        "message": "Rust service uses compiled extension points; dynamic Python plugins are not loaded."
    })))
}
