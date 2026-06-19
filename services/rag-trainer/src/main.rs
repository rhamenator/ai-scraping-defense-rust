use asd_core::{health, observability_router, pg_connect_from_env, serve, ServiceConfig};
use asd_detection::{decide, FrequencyFeatures, RequestMetadata};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct TrainerState {
    pg: Option<Arc<tokio_postgres::Client>>,
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

#[derive(Serialize)]
struct LabeledRecord {
    log_data: LogRecord,
    label: String,
    bot_score: f64,
    reasons: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("rag-trainer", 8014);
    let state = TrainerState {
        pg: pg_connect_from_env().await.map(Arc::new),
    };
    ensure_training_table(state.pg.as_deref()).await;
    let app = Router::new()
        .route("/health", get(|| async { health("rag-trainer").await }))
        .route("/training/label", post(label_records))
        .route("/training/ingest", post(ingest_records))
        .route("/finetune/export", post(export_jsonl))
        .merge(observability_router("rag-trainer"))
        .with_state(state);
    serve(app, config).await
}

async fn label_records(Json(payload): Json<BatchRequest>) -> Json<serde_json::Value> {
    Json(json!({
        "status":"success",
        "records": label_batch(payload.records)
    }))
}

async fn ingest_records(
    State(state): State<TrainerState>,
    Json(payload): Json<BatchRequest>,
) -> Json<serde_json::Value> {
    let labeled = label_batch(payload.records);
    if let Some(pg) = state.pg.as_deref() {
        for record in &labeled {
            let _ = pg
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
                .await;
        }
    }
    Json(json!({"status":"success","count":labeled.len()}))
}

async fn export_jsonl(Json(payload): Json<BatchRequest>) -> Json<serde_json::Value> {
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
    Json(json!({"status":"success","jsonl":lines.join("\n"),"metadata":metadata}))
}

fn label_batch(records: Vec<LogRecord>) -> Vec<LabeledRecord> {
    records
        .into_iter()
        .map(|record| {
            let metadata = RequestMetadata {
                ip: Some(record.ip.clone()),
                method: Some(record.method.clone().unwrap_or_else(|| "GET".to_string())),
                path: Some(record.path.clone()),
                user_agent: Some(record.user_agent.clone().unwrap_or_default()),
                referer: record.referer.clone(),
                status: record.status,
                bytes: record.bytes,
                ..Default::default()
            };
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

async fn ensure_training_table(pg: Option<&tokio_postgres::Client>) {
    let Some(pg) = pg else {
        return;
    };
    let _ = pg
        .execute(
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
        .await;
}
