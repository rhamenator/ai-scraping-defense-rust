use asd_core::{
    env_string, env_u64, health, observability_router, pg_connect_from_env, record_security_event,
    redis_client_from_env, serve, tenant_key, trusted_originating_client_ip, AuditStore,
    BlocklistState, ServiceConfig,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use redis::AsyncCommands;
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};

const DEFAULT_MAX_HOPS: u64 = 250;
const DEFAULT_HOP_WINDOW_SECONDS: u64 = 86_400;

#[derive(Clone)]
struct AppState {
    pg: Option<Arc<tokio_postgres::Client>>,
    audit: AuditStore,
    blocklist: BlocklistState,
    redis: Option<redis::Client>,
    max_hops: u64,
    hop_window_seconds: u64,
    escalation: Option<EscalationForwarder>,
}

#[derive(Clone)]
struct EscalationForwarder {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("tarpit-api")?;
    let config = ServiceConfig::from_env("tarpit-api", 8003);
    let pg = pg_connect_from_env().await.map(Arc::new);
    let state = AppState {
        audit: AuditStore::from_env(pg.clone()).await?,
        pg,
        blocklist: BlocklistState::from_env().await?,
        redis: redis_client_from_env("REDIS_DB_BLOCKLIST", 0).ok(),
        max_hops: env_u64("TAR_PIT_MAX_HOPS", DEFAULT_MAX_HOPS),
        hop_window_seconds: env_u64("TAR_PIT_HOP_WINDOW_SECONDS", DEFAULT_HOP_WINDOW_SECONDS)
            .max(1),
        escalation: match env_string("ESCALATION_ENDPOINT", "") {
            endpoint if !endpoint.is_empty() => Some(EscalationForwarder {
                client: reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()?,
                endpoint,
                api_key: env_string("ESCALATION_API_KEY", ""),
            }),
            _ => None,
        },
    };
    serve(app(state), config).await
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { health("tarpit-api").await }))
        .route("/", get(root))
        .route("/tarpit/{*path}", get(tarpit))
        .route("/assets/fake.js", get(fake_js))
        .merge(observability_router("tarpit-api"))
        .with_state(state)
}

async fn root() -> impl IntoResponse {
    Html("<html><body><h1>AI Scraping Defense Rust Tarpit</h1></body></html>")
}

async fn tarpit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let ip =
        trusted_originating_client_ip(peer.ip(), &headers).unwrap_or_else(|| peer.ip().to_string());
    if let Some(count) = count_flagged_hop(&state, &ip).await {
        if count > state.max_hops {
            let reason = format!(
                "Tarpit hop limit exceeded ({count} hits in {}s)",
                state.hop_window_seconds
            );
            state.blocklist.block_with_reason(&ip, &reason).await;
            return (
                StatusCode::FORBIDDEN,
                Html(
                    "<html><head><title>Forbidden</title></head><body>Access Denied.</body></html>"
                        .to_string(),
                ),
            );
        }
    }
    record_security_event(
        &state.audit,
        "tarpit_hit",
        &ip,
        json!({"path": format!("/tarpit/{path}"), "client": ip, "reason": "Tarpit Hit"}),
    )
    .await;
    tracing::info!(path = %format!("/tarpit/{path}"), client = %ip, reason = "Tarpit Hit", "TAR_PIT HIT");
    state.blocklist.flag(ip.clone(), "Tarpit Hit").await;
    if let Some(forwarder) = state.escalation.clone() {
        let payload = json!({
            "ip": ip,
            "method": "GET",
            "path": format!("/tarpit/{path}"),
            "user_agent": headers.get("user-agent").and_then(|value| value.to_str().ok()).unwrap_or("unknown"),
            "referer": headers.get("referer").and_then(|value| value.to_str().ok()).unwrap_or("-"),
        });
        tokio::spawn(async move {
            let mut request = forwarder.client.post(&forwarder.endpoint).json(&payload);
            if !forwarder.api_key.is_empty() {
                request = request.header("x-api-key", &forwarder.api_key);
            }
            if let Err(_error) = request.send().await {
                tracing::warn!("tarpit escalation forwarding failed");
            }
        });
    }
    let content = markov_content(state.pg.as_deref()).await;
    (
        StatusCode::OK,
        Html(asd_tarpit::generate_page_with_content(Some(&path), content)),
    )
}

async fn count_flagged_hop(state: &AppState, ip: &str) -> Option<u64> {
    if state.max_hops == 0 {
        return None;
    }
    let client = state.redis.as_ref()?;
    let mut con = match client.get_multiplexed_async_connection().await {
        Ok(con) => con,
        Err(_error) => {
            tracing::warn!("Redis unavailable for tarpit hop check");
            return None;
        }
    };
    let flag_key = tenant_key(&format!("ip_flag:{ip}"));
    let flagged: bool = match con.exists(flag_key).await {
        Ok(flagged) => flagged,
        Err(_error) => {
            tracing::warn!("Redis flag check failed");
            return None;
        }
    };
    if !flagged {
        return None;
    }
    let key = tenant_key(&format!("tarpit:hops:{ip}"));
    let result: redis::RedisResult<(u64, bool)> = redis::pipe()
        .atomic()
        .cmd("INCR")
        .arg(&key)
        .cmd("EXPIRE")
        .arg(&key)
        .arg(state.hop_window_seconds)
        .query_async(&mut con)
        .await;
    match result {
        Ok((count, _)) => Some(count),
        Err(_error) => {
            tracing::warn!("Redis tarpit hop check failed");
            None
        }
    }
}

async fn fake_js() -> impl IntoResponse {
    (
        [("content-type", "application/javascript")],
        asd_tarpit::fake_js_module(16 * 1024),
    )
}

async fn markov_content(pg: Option<&tokio_postgres::Client>) -> Option<String> {
    let pg = pg?;
    let rows = pg
        .query(
            "SELECT word FROM markov_words WHERE word <> '' ORDER BY random() LIMIT 180",
            &[],
        )
        .await
        .ok()?;
    if rows.is_empty() {
        return None;
    }
    let words = rows
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    let mut paragraphs = Vec::new();
    for chunk in words.chunks(45) {
        paragraphs.push(format!("<p>{}.</p>", html_escape(chunk.join(" "))));
    }
    Some(paragraphs.join("\n"))
}

fn html_escape(value: String) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use asd_core::load_security_events;

    #[test]
    fn routes_build_with_axum_08() {
        let _ = app(AppState {
            pg: None,
            audit: AuditStore::Disabled,
            blocklist: BlocklistState::default(),
            redis: None,
            max_hops: 250,
            hop_window_seconds: 86400,
            escalation: None,
        });
    }

    #[tokio::test]
    async fn flagged_hops_limit_expiry_disable_and_redis_failure() {
        let Ok(url) = std::env::var("TARPIT_TEST_REDIS_URL") else {
            return;
        };
        let client = redis::Client::open(url).unwrap();
        let mut con = client.get_multiplexed_async_connection().await.unwrap();
        let ip = format!("198.51.100.{}", std::process::id() % 200 + 1);
        let flag_key = tenant_key(&format!("ip_flag:{ip}"));
        let hop_key = tenant_key(&format!("tarpit:hops:{ip}"));
        let block_key = tenant_key(&format!("blocklist:{ip}"));
        let _: () = redis::cmd("DEL")
            .arg(&[&flag_key, &hop_key, &block_key])
            .query_async(&mut con)
            .await
            .unwrap();
        let mut state = AppState {
            pg: None,
            audit: AuditStore::Disabled,
            blocklist: BlocklistState::from_env().await.unwrap(),
            redis: Some(client.clone()),
            max_hops: 2,
            hop_window_seconds: 1,
            escalation: None,
        };
        assert_eq!(count_flagged_hop(&state, &ip).await, None);
        let _: () = con.set(&flag_key, "Tarpit Hit").await.unwrap();
        assert_eq!(count_flagged_hop(&state, &ip).await, Some(1));
        assert_eq!(count_flagged_hop(&state, &ip).await, Some(2));
        assert_eq!(count_flagged_hop(&state, &ip).await, Some(3));
        let reason = "Tarpit hop limit exceeded (3 hits in 1s)";
        assert!(state.blocklist.block_with_reason(&ip, reason).await);
        let stored: String = con.get(&block_key).await.unwrap();
        assert_eq!(stored, reason);
        let ttl: i64 = con.ttl(&block_key).await.unwrap();
        assert!(ttl > 0 && ttl <= 86_400);
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        assert_eq!(count_flagged_hop(&state, &ip).await, Some(1));
        state.max_hops = 0;
        assert_eq!(count_flagged_hop(&state, &ip).await, None);
        state.max_hops = 2;
        state.redis = Some(redis::Client::open("redis://127.0.0.1:1/").unwrap());
        assert_eq!(count_flagged_hop(&state, &ip).await, None);
        state.redis = Some(client);
        state.hop_window_seconds = 60;
        let _: usize = redis::cmd("DEL")
            .arg(&[&flag_key, &hop_key, &block_key])
            .query_async(&mut con)
            .await
            .unwrap();
        let audit_path =
            std::env::temp_dir().join(format!("tarpit-hit-test-{}.jsonl", std::process::id()));
        state.audit = AuditStore::jsonl(&audit_path).await.unwrap();
        let peer = SocketAddr::new(ip.parse().unwrap(), 12345);
        for expected in [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::FORBIDDEN,
        ] {
            let response = tarpit(
                State(state.clone()),
                ConnectInfo(peer),
                HeaderMap::new(),
                Path("decoy".to_string()),
            )
            .await
            .into_response();
            assert_eq!(response.status(), expected);
        }
        let events = load_security_events(&state.audit, 10).await;
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|event| event.event_type == "tarpit_hit"
            && event.actor == ip
            && event.payload["path"] == "/tarpit/decoy"
            && event.payload["reason"] == "Tarpit Hit"));
        let stored: String = con.get(&block_key).await.unwrap();
        assert_eq!(stored, "Tarpit hop limit exceeded (3 hits in 60s)");
        std::fs::remove_file(audit_path).unwrap();
        let _: () = redis::cmd("DEL")
            .arg(&[&flag_key, &hop_key, &block_key])
            .query_async(&mut con)
            .await
            .unwrap();
    }
}
