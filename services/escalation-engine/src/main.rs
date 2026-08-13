use asd_core::{
    env_string, env_u64, health, is_authorized, load_security_events, metrics_text,
    observability_router, pg_connect_from_env, record_security_event, redis_client_from_env, serve,
    tenant_key, AuditStore, BlocklistState, ServiceConfig,
};
use asd_detection::{
    decide_with_model, load_trained_model, FrequencyFeatures, InMemoryFrequency, RequestMetadata,
    TrainedLinearModel,
};
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
    audit: AuditStore,
    model: Arc<std::sync::RwLock<Option<Arc<TrainedLinearModel>>>>,
    model_path: Option<Arc<String>>,
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
    let _telemetry = asd_core::init_tracing("escalation-engine")?;
    let config = ServiceConfig::from_env("escalation-engine", 8002);
    let pg = pg_connect_from_env().await.map(Arc::new);
    let model_path = std::env::var("DETECTION_MODEL_PATH")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(Arc::new);
    let model = load_model_at_startup(model_path.as_deref().map(String::as_str))?;
    tracing::info!(
        model = if model.is_some() {
            "trained"
        } else {
            "heuristic"
        },
        "configured request detector"
    );
    let state = AppState {
        config: config.clone(),
        frequency: FrequencyStore::from_env().await,
        blocklist: BlocklistState::from_env().await,
        audit: AuditStore::from_env(pg).await?,
        model: Arc::new(std::sync::RwLock::new(model)),
        model_path,
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
        .route("/admin/reload_model", post(reload_model))
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
    let model = state
        .model
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let mut decision = decide_with_model(
        metadata,
        freq,
        state.config.throttle_threshold,
        state.config.tarpit_threshold,
        state.config.block_threshold,
        model.as_deref(),
    );
    if decision.is_bot {
        state.bots.fetch_add(1, Ordering::Relaxed);
    }
    if decision.action == "block_ip" && ip != "unknown" && !state.blocklist.block(ip.clone()).await
    {
        decision.action = "observe".to_string();
        decision.reason.push_str(
            "; block suppressed because the address is invalid or trusted infrastructure",
        );
    }
    record_security_event(
        &state.audit,
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
    Json(json!({"events": load_security_events(&state.audit, 100).await}))
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
        &state.audit,
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

/// Load the trained detector from disk, or fall back to heuristics when no
/// path is configured. A configured-but-unreadable model is an error so a
/// bad artifact never silently downgrades detection. Used directly by
/// `/admin/reload_model`, where a missing file must still be reported as an
/// error rather than silently keeping the previous detector.
fn load_model(path: Option<&str>) -> anyhow::Result<Option<Arc<TrainedLinearModel>>> {
    path.map(load_trained_model)
        .transpose()
        .map(|model| model.map(Arc::new))
}

/// Startup variant of `load_model`: a configured path whose file does not
/// exist yet (e.g. a freshly created, still-empty detection-model volume on
/// first deploy) falls back to heuristic detection instead of failing to
/// start, since rag-trainer has simply not persisted a model yet. A path
/// that exists but is malformed or otherwise unreadable is still a hard
/// startup failure, same as `load_model`. Uses `try_exists` rather than
/// `exists`: `exists` collapses any stat error (including permission
/// denied) to `false`, which would silently downgrade an unreadable
/// artifact to heuristic detection instead of failing closed; `try_exists`
/// only reports "missing" for a genuine not-found and propagates other
/// I/O errors.
fn load_model_at_startup(path: Option<&str>) -> anyhow::Result<Option<Arc<TrainedLinearModel>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    match std::path::Path::new(path).try_exists() {
        Ok(true) => load_model(Some(path)),
        Ok(false) => {
            tracing::warn!(
                path,
                "no detection model artifact at the configured path yet; starting with heuristic detection"
            );
            Ok(None)
        }
        Err(exc) => Err(anyhow::anyhow!(
            "failed to check detection model artifact at {path}: {exc}"
        )),
    }
}

async fn reload_model(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ESCALATION_API_KEY", "JWT_SECRET") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status":"error","message":"Unauthorized"})),
        ));
    }
    let Some(path) = state.model_path.as_deref() else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status":"error",
                "message":"DETECTION_MODEL_PATH is not configured; nothing to reload"
            })),
        ));
    };
    let model = load_model(Some(path)).map_err(|exc| {
        tracing::error!(error = %exc, path, "failed to reload trained model; keeping current detector");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status":"error",
                "message":"failed to load the model artifact; the previous detector remains active"
            })),
        )
    })?;
    *state
        .model
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = model;
    record_security_event(
        &state.audit,
        "admin_reload_model",
        "admin",
        json!({"service":"escalation-engine","model_path":path}),
    )
    .await;
    Ok(Json(json!({
        "status":"success",
        "detector":"trained",
        "model_path":path
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asd_detection::MODEL_FEATURE_NAMES;

    fn temp_model_path(tag: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "escalation-model-{tag}-{}-{unique}.json",
            std::process::id()
        ))
    }

    #[test]
    fn model_reload_swaps_in_a_persisted_artifact() {
        let path = temp_model_path("valid");
        let artifact = json!({
            "schema_version": 1,
            "algorithm": "logistic_regression",
            "feature_names": MODEL_FEATURE_NAMES,
            "weights": vec![0.1; MODEL_FEATURE_NAMES.len()],
            "bias": -0.5
        });
        std::fs::write(&path, artifact.to_string()).unwrap();

        let slot: std::sync::RwLock<Option<Arc<TrainedLinearModel>>> = std::sync::RwLock::new(None);
        let loaded = load_model(path.to_str()).expect("valid artifact should load");
        *slot.write().unwrap() = loaded;
        assert!(slot.read().unwrap().is_some());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unreadable_or_invalid_artifacts_do_not_replace_the_detector() {
        assert!(load_model(Some("does-not-exist.json")).is_err());

        let path = temp_model_path("invalid");
        std::fs::write(&path, "{\"not\":\"a model\"}").unwrap();
        assert!(load_model(path.to_str()).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn no_configured_path_means_heuristic_detection() {
        assert!(load_model(None).expect("heuristic fallback").is_none());
    }

    #[test]
    fn missing_artifact_at_startup_falls_back_to_heuristic_detection() {
        // A fresh, still-empty shared volume must not block startup.
        let path = temp_model_path("missing-at-startup");
        assert!(!path.exists());
        assert!(load_model_at_startup(path.to_str())
            .expect("missing artifact at startup should fall back to heuristics")
            .is_none());
    }

    #[test]
    fn existing_malformed_artifact_still_fails_startup() {
        let path = temp_model_path("malformed-at-startup");
        std::fs::write(&path, "{\"not\":\"a model\"}").unwrap();
        assert!(load_model_at_startup(path.to_str()).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_artifact_directory_fails_startup_instead_of_falling_back() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_model_path("unreadable-dir");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("detection-model.json");
        std::fs::write(&path, "{}").unwrap();
        // Strip all permissions from the containing directory so stat()
        // during try_exists() fails with PermissionDenied rather than
        // NotFound; load_model_at_startup must propagate that error rather
        // than treating it as "artifact not present yet".
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = load_model_at_startup(path.to_str());

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(
            result.is_err(),
            "a permission error while checking the artifact must fail closed, not silently fall back to heuristics"
        );
    }

    #[test]
    fn reload_still_errors_when_artifact_is_missing() {
        // /admin/reload_model must never silently keep serving the previous
        // detector when told to load a path that isn't there.
        assert!(load_model(Some("definitely-does-not-exist.json")).is_err());
    }
}
