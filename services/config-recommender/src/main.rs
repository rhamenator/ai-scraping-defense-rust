use asd_core::{
    env_string, env_u64, has_valid_api_key, health, observability_router, serve, ServiceConfig,
};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

#[derive(Clone)]
struct IncidentState {
    client: reqwest::Client,
    last_alert: Arc<Mutex<HashMap<String, u64>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("config-recommender")?;
    let config = ServiceConfig::from_env("config-recommender", 8007);
    let state = IncidentState {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?,
        last_alert: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route(
            "/health",
            get(|| async { health("config-recommender").await }),
        )
        .route("/recommendations", get(recommendations))
        .route("/incident/evaluate", post(evaluate_incident))
        .merge(observability_router("config-recommender"))
        .with_state(state);
    serve(app, config).await
}

#[derive(Deserialize)]
struct IncidentSignal {
    site_id: String,
    window_start: u64,
    window_end: u64,
    total_requests: u64,
    bot_requests: u64,
    unique_source_ips: u64,
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn attack_signal(signal: &IncidentSignal, now: u64) -> bool {
    let duration = signal.window_end.saturating_sub(signal.window_start);
    let max_window = env_u64("INCIDENT_MAX_WINDOW_SECONDS", 300).clamp(30, 3600);
    let min_sources = env_u64("INCIDENT_MIN_UNIQUE_SOURCES", 20).max(2);
    let min_requests = env_u64("CLOUDFLARE_ATTACK_RECOMMENDATION_MIN_REQUESTS", 100);
    let min_bot_ratio = env_string("CLOUDFLARE_ATTACK_RECOMMENDATION_MIN_BOT_RATIO", "0.25")
        .parse::<f64>()
        .unwrap_or(0.25)
        .clamp(0.0, 1.0);
    duration > 0
        && duration <= max_window
        && signal.window_end <= now.saturating_add(30)
        && now.saturating_sub(signal.window_end) <= 60
        && signal.total_requests >= min_requests
        && signal.unique_source_ips >= min_sources
        && signal.unique_source_ips <= signal.total_requests
        && signal.bot_requests <= signal.total_requests
        && signal.bot_requests as f64 / signal.total_requests as f64 >= min_bot_ratio
}

async fn origin_healthy(client: &reqwest::Client, url: &str) -> Option<bool> {
    if url.is_empty() {
        return None;
    }
    Some(
        client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success()),
    )
}

async fn evaluate_incident(
    State(state): State<IncidentState>,
    headers: HeaderMap,
    Json(signal): Json<IncidentSignal>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let key = env_string("INCIDENT_EVALUATOR_API_KEY", "");
    if key.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"incident evaluator key not configured"})),
        ));
    }
    if !has_valid_api_key(&headers, &key) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        ));
    }
    if signal.site_id.is_empty()
        || signal.site_id.len() > 128
        || !signal
            .site_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid site_id"})),
        ));
    }
    let now = now_seconds();
    if !attack_signal(&signal, now) {
        return Ok(Json(
            json!({"incident":false,"alert_sent":false,"choices":[]}),
        ));
    }
    let webhook = env_string("ADMIN_ALERT_WEBHOOK_URL", "");
    if webhook.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"admin alert webhook not configured"})),
        ));
    }
    let cooldown = env_u64("INCIDENT_ALERT_COOLDOWN_SECONDS", 900).max(60);
    let mut last_alert = state.last_alert.lock().await;
    last_alert.retain(|_, last| now.saturating_sub(*last) < cooldown);
    if last_alert
        .get(&signal.site_id)
        .is_some_and(|last| now.saturating_sub(*last) < cooldown)
    {
        return Ok(Json(
            json!({"incident":true,"alert_sent":false,"deduplicated":true,"choices":[]}),
        ));
    }
    let primary = origin_healthy(
        &state.client,
        &env_string("INCIDENT_PRIMARY_HEALTH_URL", ""),
    )
    .await;
    let backup = origin_healthy(&state.client, &env_string("INCIDENT_BACKUP_HEALTH_URL", "")).await;
    let mut choices = Vec::new();
    if cloudflare_enabled() {
        choices.push(json!({
            "id":"enable-cloudflare-under-attack-mode", "manual":true,
            "message":"Review the evidence, then manually enable Cloudflare Under Attack Mode for the affected zone."
        }));
    }
    if primary == Some(false) && backup == Some(true) {
        choices.push(json!({"id":"failover-to-backup", "manual":true,
            "message":"Primary origin is unhealthy and backup is healthy; review and initiate failover."}));
    }
    let alert = json!({
        "event":"attack_incident", "severity":"high", "site_id":signal.site_id,
        "window_start":signal.window_start, "window_end":signal.window_end,
        "total_requests":signal.total_requests, "bot_requests":signal.bot_requests,
        "unique_source_ips":signal.unique_source_ips,
        "primary_healthy":primary, "backup_healthy":backup,
        "choices":choices,
    });
    let mut request = state.client.post(webhook).json(&alert);
    let token = env_string("ADMIN_ALERT_WEBHOOK_BEARER_TOKEN", "");
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            last_alert.insert(signal.site_id, now);
            Ok(Json(
                json!({"incident":true,"alert_sent":true,"deduplicated":false,"choices":choices}),
            ))
        }
        _ => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":"admin alert delivery failed"})),
        )),
    }
}

#[derive(Default, Deserialize)]
struct RecommendationQuery {
    total_requests: Option<u64>,
    bot_requests: Option<u64>,
}

async fn recommendations(Query(query): Query<RecommendationQuery>) -> Json<serde_json::Value> {
    let total_requests = query.total_requests.unwrap_or_default();
    let bot_requests = query.bot_requests.unwrap_or_default();
    let cloudflare_enabled = cloudflare_enabled();
    let minimum_requests = env_u64("CLOUDFLARE_ATTACK_RECOMMENDATION_MIN_REQUESTS", 100);
    let minimum_bot_ratio = env_string("CLOUDFLARE_ATTACK_RECOMMENDATION_MIN_BOT_RATIO", "0.25")
        .parse::<f64>()
        .unwrap_or(0.25)
        .clamp(0.0, 1.0);
    let recommend_under_attack = should_recommend_cloudflare(
        cloudflare_enabled,
        total_requests,
        bot_requests,
        minimum_requests,
        minimum_bot_ratio,
    );

    Json(json!({
        "rate_limit_per_minute": 120,
        "escalation_threshold": 0.70,
        "tarpit_threshold": 0.82,
        "block_threshold": 0.92,
        "source": "rust-baseline",
        "operator_recommendations": if recommend_under_attack {
            vec![json!({
                "id": "enable-cloudflare-under-attack-mode",
                "severity": "high",
                "advisory": true,
                "message": "Review the attack evidence and consider enabling Cloudflare Under Attack Mode for the affected zone.",
                "bot_ratio": bot_requests.min(total_requests) as f64 / total_requests as f64,
                "origin_ip_only": true
            })]
        } else {
            Vec::new()
        }
    }))
}

fn cloudflare_enabled() -> bool {
    matches!(
        env_string("ENABLE_GLOBAL_CDN", "false")
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    ) && env_string("CLOUD_CDN_PROVIDER", "cloudflare").eq_ignore_ascii_case("cloudflare")
}

fn should_recommend_cloudflare(
    enabled: bool,
    total_requests: u64,
    bot_requests: u64,
    minimum_requests: u64,
    minimum_bot_ratio: f64,
) -> bool {
    enabled
        && total_requests >= minimum_requests
        && total_requests > 0
        && bot_requests.min(total_requests) as f64 / total_requests as f64 >= minimum_bot_ratio
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_configured_origin_is_unhealthy() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        assert_eq!(origin_healthy(&client, "").await, None);
        assert_eq!(
            origin_healthy(&client, "http://127.0.0.1:0/health").await,
            Some(false)
        );
    }

    #[test]
    fn cloudflare_recommendation_requires_integration_and_attack_evidence() {
        assert!(!should_recommend_cloudflare(false, 1_000, 900, 100, 0.25));
        assert!(!should_recommend_cloudflare(true, 99, 99, 100, 0.25));
        assert!(!should_recommend_cloudflare(true, 1_000, 100, 100, 0.25));
        assert!(should_recommend_cloudflare(true, 1_000, 300, 100, 0.25));
    }

    #[test]
    fn cloudflare_ratio_clamps_impossible_bot_counts() {
        assert!(should_recommend_cloudflare(true, 100, 500, 100, 1.0));
    }

    #[test]
    fn incident_requires_recent_distributed_attack_window() {
        let now = 1_000_000;
        let mut signal = IncidentSignal {
            site_id: "example.test".into(),
            window_start: now - 120,
            window_end: now,
            total_requests: 1_000,
            bot_requests: 400,
            unique_source_ips: 50,
        };
        assert!(attack_signal(&signal, now));
        signal.window_start = now - 300;
        signal.window_end = now - 120;
        assert!(!attack_signal(&signal, now));
        signal.window_start = now - 120;
        signal.window_end = now;
        signal.unique_source_ips = 1;
        assert!(!attack_signal(&signal, now));
        signal.unique_source_ips = 50;
        signal.bot_requests = 100;
        assert!(!attack_signal(&signal, now));
    }
}
