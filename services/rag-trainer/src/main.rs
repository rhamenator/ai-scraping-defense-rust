use asd_core::{
    health, is_authorized, observability_router, pg_connect_from_env, serve, ServiceConfig,
};
use asd_detection::{
    decide, extract_features, model_feature_vector, FrequencyFeatures, RequestMetadata,
    TrainedLinearModel, MODEL_FEATURE_NAMES,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

const MAX_TRAINING_RECORDS: usize = 10_000;
const MAX_TRAINING_STEPS: usize = 2_000_000;

#[derive(Clone)]
struct TrainerState {
    pg: Option<Arc<tokio_postgres::Client>>,
    model_path: Option<Arc<PathBuf>>,
}

#[derive(Clone, Deserialize, Serialize)]
struct LogRecord {
    ip: String,
    method: Option<String>,
    path: String,
    status: Option<u16>,
    bytes: Option<u64>,
    referer: Option<String>,
    user_agent: Option<String>,
}

#[derive(Deserialize)]
struct BatchRequest {
    records: Vec<LogRecord>,
}

#[derive(Deserialize)]
struct ReviewedTrainingRecord {
    log_data: LogRecord,
    label: String,
}

#[derive(Deserialize)]
struct TrainModelRequest {
    records: Vec<ReviewedTrainingRecord>,
    epochs: Option<usize>,
    learning_rate: Option<f64>,
    #[serde(default)]
    persist: bool,
}

#[derive(Serialize)]
struct LabeledRecord {
    log_data: LogRecord,
    label: String,
    bot_score: f64,
    reasons: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("rag-trainer")?;
    let config = ServiceConfig::from_env("rag-trainer", 8014);
    let state = TrainerState {
        pg: pg_connect_from_env().await.map(Arc::new),
        model_path: std::env::var("DETECTION_MODEL_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty())
            .map(|path| Arc::new(PathBuf::from(path))),
    };
    ensure_training_table(state.pg.as_deref()).await?;
    let app = Router::new()
        .route("/health", get(|| async { health("rag-trainer").await }))
        .route("/training/label", post(label_records))
        .route("/training/ingest", post(ingest_records))
        .route("/training/train", post(train_model))
        .route("/finetune/export", post(export_jsonl))
        .merge(observability_router("rag-trainer"))
        .with_state(state);
    serve(app, config).await
}

type ApiError = (StatusCode, Json<serde_json::Value>);

/// Training data and model artifacts are a poisoning/resource-abuse vector,
/// so every non-observability route requires the same API-key/JWT gate the
/// other admin surfaces use. Fails closed when no secret is configured.
fn authorize(headers: &HeaderMap) -> Result<(), ApiError> {
    if is_authorized(headers, "RAG_TRAINER_API_KEY", "JWT_SECRET") {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status":"error","message":"Unauthorized"})),
        ))
    }
}

async fn label_records(
    headers: HeaderMap,
    Json(payload): Json<BatchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers)?;
    Ok(Json(json!({
        "status":"success",
        "records": label_batch(payload.records)
    })))
}

async fn ingest_records(
    State(state): State<TrainerState>,
    headers: HeaderMap,
    Json(payload): Json<BatchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers)?;
    let labeled = label_batch(payload.records);
    if let Some(pg) = state.pg.as_deref() {
        for record in &labeled {
            pg
                .execute(
                    "INSERT INTO training_requests
                     (ip, method, path, status, bytes, referer, user_agent, bot_score, label, reasons)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                    &[
                        &record.log_data.ip,
                        &record.log_data.method,
                        &record.log_data.path,
                        &(record.log_data.status.map(i32::from)),
                        &(record.log_data.bytes.map(|value| value as i64)),
                        &record.log_data.referer,
                        &record.log_data.user_agent,
                        &record.bot_score,
                        &record.label,
                        &json!(record.reasons),
                    ],
                )
                .await
                .map_err(|exc| {
                    tracing::error!(error = %exc, "failed to persist training record");
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"status":"error","message":"training database unavailable"})),
                    )
                })?;
        }
    }
    Ok(Json(json!({"status":"success","count":labeled.len()})))
}

async fn export_jsonl(
    headers: HeaderMap,
    Json(payload): Json<BatchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers)?;
    let labeled = label_batch(payload.records);
    let lines = labeled
        .iter()
        .filter(|record| matches!(record.label.as_str(), "bot" | "human"))
        .map(|record| {
            json!({
                "log_data": serde_json::to_string(&record.log_data).unwrap_or_default(),
                "label": record.label
            })
            .to_string()
        })
        .collect::<Vec<_>>();
    let metadata = json!({
        "schema_version": 1,
        "generated_at": Utc::now(),
        "generated_by": "rag-trainer",
        "record_count": lines.len(),
        "trust_boundary": {
            "review_required": true,
            "notes": "Heuristic labels should be reviewed before fine-tuning or sharing model artifacts."
        }
    });
    Ok(Json(
        json!({"status":"success","jsonl":lines.join("\n"),"metadata":metadata}),
    ))
}

async fn train_model(
    State(state): State<TrainerState>,
    headers: HeaderMap,
    Json(payload): Json<TrainModelRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers)?;
    let persist = payload.persist;
    if persist && state.model_path.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status":"error",
                "message":"persist requested but DETECTION_MODEL_PATH is not configured"
            })),
        ));
    }
    let (model, accuracy) = fit_model(payload).map_err(|message| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"status":"error","message":message})),
        )
    })?;
    let persisted_to = if persist {
        let path = state.model_path.as_deref().expect("checked above");
        persist_model(path, &model).map_err(|exc| {
            tracing::error!(error = %exc, path = %path.display(), "failed to persist trained model");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status":"error","message":"failed to persist trained model"})),
            )
        })?;
        Some(path.display().to_string())
    } else {
        None
    };
    Ok(Json(json!({
        "status":"success",
        "model":model,
        "persisted_to":persisted_to,
        "metrics":{
            "training_accuracy":accuracy,
            "reviewed_labels_required":true
        }
    })))
}

/// Monotonic counter that, combined with the process id and a nanosecond
/// timestamp, keeps every persist_model call's temp file name unique even
/// when two training requests are persisted concurrently in the same
/// process.
static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(path: &Path) -> PathBuf {
    let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(".{}.{nanos}.{seq}.tmp", std::process::id()));
    PathBuf::from(temp)
}

/// Write the model atomically (unique temp file + rename) so a concurrent
/// escalation-engine reload never observes a partially written artifact and
/// overlapping training requests never race on the same temp file name.
/// std::fs::rename replaces an existing destination on both Unix and Windows
/// (MOVEFILE_REPLACE_EXISTING), so repeated training runs overwrite in place
/// and concurrent persists resolve to whichever rename lands last, never a
/// mix of two artifacts; the temp artifact is removed if its own rename
/// fails (e.g. a Windows sharing violation while the destination is held
/// open).
fn persist_model(path: &Path, model: &TrainedLinearModel) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let temp = unique_temp_path(path);
    std::fs::write(&temp, serde_json::to_vec_pretty(model)?)?;
    if let Err(exc) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(exc.into());
    }
    Ok(())
}

fn fit_model(request: TrainModelRequest) -> Result<(TrainedLinearModel, f64), String> {
    let record_count = request.records.len();
    if record_count < 2 {
        return Err("at least two reviewed training records are required".into());
    }
    if record_count > MAX_TRAINING_RECORDS {
        return Err(format!(
            "at most {MAX_TRAINING_RECORDS} training records are accepted per request"
        ));
    }
    let epochs = request.epochs.unwrap_or(400).clamp(10, 10_000);
    if record_count.saturating_mul(epochs) > MAX_TRAINING_STEPS {
        return Err(format!(
            "training request exceeds the {MAX_TRAINING_STEPS} record-epoch work limit"
        ));
    }

    let mut samples = Vec::with_capacity(record_count);
    let mut saw_bot = false;
    let mut saw_human = false;
    for record in request.records {
        let label = match record.label.trim().to_ascii_lowercase().as_str() {
            "bot" => {
                saw_bot = true;
                1.0
            }
            "human" => {
                saw_human = true;
                0.0
            }
            _ => return Err("reviewed labels must be either 'bot' or 'human'".into()),
        };
        let metadata = metadata_from_log(&record.log_data);
        let features = extract_features(&metadata, FrequencyFeatures::default());
        samples.push((model_feature_vector(&features), label));
    }
    if !saw_bot || !saw_human {
        return Err("training data must contain both bot and human reviewed labels".into());
    }

    let learning_rate = request.learning_rate.unwrap_or(0.2).clamp(0.0001, 1.0);
    let mut weights = vec![0.0; MODEL_FEATURE_NAMES.len()];
    let mut bias = 0.0;
    for _ in 0..epochs {
        let mut weight_gradient = vec![0.0; weights.len()];
        let mut bias_gradient = 0.0;
        for (features, label) in &samples {
            let linear = weights
                .iter()
                .zip(features)
                .fold(bias, |sum, (weight, feature)| sum + weight * feature);
            let prediction = 1.0 / (1.0 + (-linear).exp());
            let error = prediction - label;
            for (gradient, feature) in weight_gradient.iter_mut().zip(features) {
                *gradient += error * feature;
            }
            bias_gradient += error;
        }
        let scale = learning_rate / samples.len() as f64;
        for (weight, gradient) in weights.iter_mut().zip(weight_gradient) {
            *weight -= scale * gradient;
        }
        bias -= scale * bias_gradient;
    }

    let model = TrainedLinearModel {
        schema_version: 1,
        algorithm: "logistic_regression".into(),
        feature_names: MODEL_FEATURE_NAMES.map(str::to_string).to_vec(),
        weights,
        bias,
    };
    model.validate()?;
    let correct = samples
        .iter()
        .filter(|(features, label)| {
            let linear = model
                .weights
                .iter()
                .zip(features)
                .fold(model.bias, |sum, (weight, feature)| sum + weight * feature);
            let prediction = 1.0 / (1.0 + (-linear).exp());
            (prediction >= 0.5) == (*label >= 0.5)
        })
        .count();
    Ok((model, correct as f64 / samples.len() as f64))
}

fn metadata_from_log(record: &LogRecord) -> RequestMetadata {
    RequestMetadata {
        ip: Some(record.ip.clone()),
        method: Some(record.method.clone().unwrap_or_else(|| "GET".to_string())),
        path: Some(record.path.clone()),
        user_agent: Some(record.user_agent.clone().unwrap_or_default()),
        referer: record.referer.clone(),
        status: record.status,
        bytes: record.bytes,
        ..Default::default()
    }
}

fn label_batch(records: Vec<LogRecord>) -> Vec<LabeledRecord> {
    records
        .into_iter()
        .map(|record| {
            let metadata = metadata_from_log(&record);
            let mut decision = decide(metadata, FrequencyFeatures::default(), 0.7, 0.82, 0.92);
            if record.status.is_some_and(|status| status >= 400) {
                decision.score = (decision.score + 0.10).min(1.0);
            }
            let label = if decision.score >= 0.8 {
                "bot"
            } else if decision.score <= 0.5 {
                "human"
            } else {
                "suspicious"
            };
            LabeledRecord {
                log_data: record,
                label: label.to_string(),
                bot_score: decision.score,
                reasons: vec![decision.reason],
            }
        })
        .collect()
}

async fn ensure_training_table(pg: Option<&tokio_postgres::Client>) -> anyhow::Result<()> {
    let Some(pg) = pg else {
        return Ok(());
    };
    pg.execute(
        "CREATE TABLE IF NOT EXISTS training_requests (
                id BIGSERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                method TEXT,
                path TEXT NOT NULL,
                status INTEGER,
                bytes BIGINT,
                referer TEXT,
                user_agent TEXT,
                bot_score DOUBLE PRECISION NOT NULL,
                label TEXT NOT NULL,
                reasons JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        &[],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(user_agent: &str, path: &str, label: &str) -> ReviewedTrainingRecord {
        ReviewedTrainingRecord {
            log_data: LogRecord {
                ip: "198.51.100.20".into(),
                method: Some("GET".into()),
                path: path.into(),
                status: Some(200),
                bytes: Some(100),
                referer: Some("https://example.test/".into()),
                user_agent: Some(user_agent.into()),
            },
            label: label.into(),
        }
    }

    #[test]
    fn reviewed_labels_train_a_valid_predictive_artifact() {
        let (model, accuracy) = fit_model(TrainModelRequest {
            records: vec![
                record("python-requests/2", "/.env", "bot"),
                record("Scrapy/2", "/wp-admin", "bot"),
                record("Mozilla/5.0", "/", "human"),
                record("Mozilla/5.0", "/products", "human"),
            ],
            epochs: Some(800),
            learning_rate: Some(0.2),
            persist: false,
        })
        .expect("reviewed binary labels should train");

        assert_eq!(model.schema_version, 1);
        assert_eq!(model.weights.len(), MODEL_FEATURE_NAMES.len());
        assert!(accuracy >= 0.75);
        assert!(serde_json::to_string(&model).is_ok());
    }

    #[test]
    fn training_rejects_single_class_or_unreviewed_labels() {
        assert!(fit_model(TrainModelRequest {
            records: vec![
                record("python-requests/2", "/.env", "bot"),
                record("Scrapy/2", "/wp-admin", "bot"),
            ],
            epochs: None,
            learning_rate: None,
            persist: false,
        })
        .is_err());
        assert!(fit_model(TrainModelRequest {
            records: vec![
                record("python-requests/2", "/.env", "suspicious"),
                record("Mozilla/5.0", "/", "human"),
            ],
            epochs: None,
            learning_rate: None,
            persist: false,
        })
        .is_err());
    }

    #[test]
    fn training_rejects_unbounded_memory_and_cpu_requests() {
        let too_many_records = (0..=MAX_TRAINING_RECORDS)
            .map(|index| {
                let label = if index % 2 == 0 { "bot" } else { "human" };
                record("Mozilla/5.0", "/", label)
            })
            .collect();
        assert!(fit_model(TrainModelRequest {
            records: too_many_records,
            epochs: Some(10),
            learning_rate: None,
            persist: false,
        })
        .is_err());

        let expensive_records = (0..=(MAX_TRAINING_STEPS / 10_000))
            .map(|index| {
                let label = if index % 2 == 0 { "bot" } else { "human" };
                record("Mozilla/5.0", "/", label)
            })
            .collect();
        assert!(fit_model(TrainModelRequest {
            records: expensive_records,
            epochs: Some(10_000),
            learning_rate: None,
            persist: false,
        })
        .is_err());
    }

    // is_authorized reads env vars at call time; serialize env-touching tests.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn training_payload() -> TrainModelRequest {
        TrainModelRequest {
            records: vec![
                record("python-requests/2", "/.env", "bot"),
                record("Scrapy/2", "/wp-admin", "bot"),
                record("Mozilla/5.0", "/", "human"),
                record("Mozilla/5.0", "/products", "human"),
            ],
            epochs: Some(200),
            learning_rate: Some(0.2),
            persist: false,
        }
    }

    fn state(model_path: Option<PathBuf>) -> TrainerState {
        TrainerState {
            pg: None,
            model_path: model_path.map(Arc::new),
        }
    }

    #[tokio::test]
    async fn training_routes_fail_closed_without_configured_secrets() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("RAG_TRAINER_API_KEY");
        std::env::remove_var("JWT_SECRET");

        let batch = BatchRequest { records: vec![] };
        assert!(matches!(
            label_records(HeaderMap::new(), Json(BatchRequest { records: vec![] })).await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
        assert!(matches!(
            ingest_records(State(state(None)), HeaderMap::new(), Json(batch)).await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
        assert!(matches!(
            export_jsonl(HeaderMap::new(), Json(BatchRequest { records: vec![] })).await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
        assert!(matches!(
            train_model(
                State(state(None)),
                HeaderMap::new(),
                Json(training_payload())
            )
            .await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
    }

    #[tokio::test]
    async fn training_routes_reject_wrong_key_and_accept_configured_key() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var("RAG_TRAINER_API_KEY", "trainer-test-key");
        std::env::remove_var("JWT_SECRET");

        let mut wrong = HeaderMap::new();
        wrong.insert("x-api-key", "not-the-key".parse().unwrap());
        assert!(matches!(
            train_model(State(state(None)), wrong, Json(training_payload())).await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));

        let mut authorized = HeaderMap::new();
        authorized.insert("x-api-key", "trainer-test-key".parse().unwrap());
        let response = train_model(State(state(None)), authorized, Json(training_payload()))
            .await
            .expect("authorized training request should succeed");
        assert_eq!(response.0["status"], "success");

        std::env::remove_var("RAG_TRAINER_API_KEY");
    }

    #[tokio::test]
    async fn persist_writes_a_model_the_escalation_engine_can_load() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var("RAG_TRAINER_API_KEY", "trainer-test-key");
        std::env::remove_var("JWT_SECRET");
        let mut authorized = HeaderMap::new();
        authorized.insert("x-api-key", "trainer-test-key".parse().unwrap());

        // Persist without a configured path is rejected before any training work.
        let mut payload = training_payload();
        payload.persist = true;
        assert!(matches!(
            train_model(State(state(None)), authorized.clone(), Json(payload)).await,
            Err((StatusCode::BAD_REQUEST, _))
        ));

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rag-trainer-model-{}-{unique}.json",
            std::process::id()
        ));
        let mut payload = training_payload();
        payload.persist = true;
        let response = train_model(State(state(Some(path.clone()))), authorized, Json(payload))
            .await
            .expect("persisting training request should succeed");
        assert_eq!(response.0["persisted_to"], path.display().to_string());

        let loaded = asd_detection::load_trained_model(&path)
            .expect("persisted artifact should round-trip through the deployment loader");
        assert_eq!(loaded.weights.len(), MODEL_FEATURE_NAMES.len());

        // A second training run must overwrite the existing artifact in place
        // (rename onto an existing destination, including on Windows) and
        // leave no temp file behind.
        let mut payload = training_payload();
        payload.persist = true;
        let mut authorized = HeaderMap::new();
        authorized.insert("x-api-key", "trainer-test-key".parse().unwrap());
        let overwrite = train_model(State(state(Some(path.clone()))), authorized, Json(payload))
            .await
            .expect("re-training over an existing artifact should succeed");
        assert_eq!(overwrite.0["status"], "success");
        asd_detection::load_trained_model(&path).expect("overwritten artifact should still load");
        assert!(!any_leftover_temp_files(&path));

        std::fs::remove_file(path).unwrap();
        std::env::remove_var("RAG_TRAINER_API_KEY");
    }

    fn any_leftover_temp_files(path: &Path) -> bool {
        let Some(dir) = path.parent() else {
            return false;
        };
        let stem = path.file_name().unwrap().to_string_lossy().into_owned();
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.starts_with(&stem) && name.ends_with(".tmp")
            })
    }

    #[test]
    fn concurrent_persists_do_not_corrupt_the_artifact_or_leak_temp_files() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rag-trainer-concurrent-model-{}-{unique}.json",
            std::process::id()
        ));

        let model_a = TrainedLinearModel {
            schema_version: 1,
            algorithm: "logistic_regression".into(),
            feature_names: MODEL_FEATURE_NAMES.map(str::to_string).to_vec(),
            weights: vec![0.11; MODEL_FEATURE_NAMES.len()],
            bias: -0.5,
        };
        let model_b = TrainedLinearModel {
            weights: vec![0.99; MODEL_FEATURE_NAMES.len()],
            bias: 0.5,
            ..model_a.clone()
        };

        let (path_a, path_b) = (path.clone(), path.clone());
        let (model_a2, model_b2) = (model_a.clone(), model_b.clone());
        let writer_a = std::thread::spawn(move || persist_model(&path_a, &model_a2));
        let writer_b = std::thread::spawn(move || persist_model(&path_b, &model_b2));
        writer_a.join().unwrap().expect("writer A should persist");
        writer_b.join().unwrap().expect("writer B should persist");

        // Whichever rename lands last, the artifact is one writer's complete
        // model, never a byte-interleaved mix of both.
        let loaded = asd_detection::load_trained_model(&path)
            .expect("artifact should be valid after concurrent persists");
        assert!(loaded.weights == model_a.weights || loaded.weights == model_b.weights);
        assert!(!any_leftover_temp_files(&path));

        std::fs::remove_file(path).unwrap();
    }
}
