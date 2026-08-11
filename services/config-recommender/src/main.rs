use asd_core::{env_string, env_u64, health, observability_router, serve, ServiceConfig};
use axum::{extract::Query, routing::get, Json, Router};
use serde::Deserialize;
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("config-recommender")?;
    let config = ServiceConfig::from_env("config-recommender", 8007);
    let app = Router::new()
        .route(
            "/health",
            get(|| async { health("config-recommender").await }),
        )
        .route("/recommendations", get(recommendations))
        .merge(observability_router("config-recommender"));
    serve(app, config).await
}

#[derive(Default, Deserialize)]
struct RecommendationQuery {
    total_requests: Option<u64>,
    bot_requests: Option<u64>,
}

async fn recommendations(Query(query): Query<RecommendationQuery>) -> Json<serde_json::Value> {
    let total_requests = query.total_requests.unwrap_or_default();
    let bot_requests = query.bot_requests.unwrap_or_default();
    let cloudflare_enabled = matches!(
        env_string("ENABLE_GLOBAL_CDN", "false")
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    ) && env_string("CLOUD_CDN_PROVIDER", "cloudflare")
        .eq_ignore_ascii_case("cloudflare");
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
}
