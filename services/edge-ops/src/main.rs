use asd_core::{
    env_string, health, observability_router, record_security_event, serve, BlocklistState,
    ServiceConfig,
};
use asd_detection::{decide, FrequencyFeatures, RequestMetadata};
use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use reqwest::{redirect::Policy, Url};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, net::IpAddr, sync::Arc};

#[derive(Clone)]
struct EdgeState {
    blocklist: BlocklistState,
    pg: Option<Arc<tokio_postgres::Client>>,
}

#[derive(Deserialize)]
struct FetchQuery {
    url: Option<String>,
}

#[derive(Deserialize)]
struct WafRules {
    rules: Vec<String>,
}

#[derive(Deserialize)]
struct PathsRequest {
    paths: Vec<String>,
}

#[derive(Deserialize)]
struct SyncRequest {
    ips: Vec<String>,
    source: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("edge-ops", 8013);
    let state = EdgeState {
        blocklist: BlocklistState::from_env().await,
        pg: asd_core::pg_connect_from_env().await.map(Arc::new),
    };
    let app = Router::new()
        .route("/health", get(|| async { health("edge-ops").await }))
        .route("/robots/fetch", get(fetch_robots))
        .route("/rules/fetch", get(fetch_rules))
        .route("/waf/reload", post(reload_waf))
        .route("/cdn/purge", post(purge_cdn))
        .route("/tls/status", get(tls_status))
        .route("/ddos/status", get(ddos_status))
        .route("/sync/community-blocklist", post(sync_blocklist))
        .route("/sync/peer-blocklist", post(sync_blocklist))
        .route("/security/score", get(security_score))
        .merge(observability_router("edge-ops"))
        .with_state(state);
    serve(app, config).await
}

async fn fetch_robots(Query(query): Query<FetchQuery>) -> Json<serde_json::Value> {
    let target = query
        .url
        .unwrap_or_else(|| env_string("REAL_BACKEND_HOST", "https://example.com"));
    let Some(robots_url) = robots_url(&target) else {
        return Json(json!({"status":"error","content":default_robots()}));
    };
    match fetch_text(&robots_url, false).await {
        Ok(content) => Json(json!({"status":"success","url":robots_url,"content":content})),
        Err(message) => Json(
            json!({"status":"error","url":robots_url,"message":message,"content":default_robots()}),
        ),
    }
}

async fn fetch_rules(Query(query): Query<FetchQuery>) -> Json<serde_json::Value> {
    let target = query.url.unwrap_or_else(|| env_string("RULES_URL", ""));
    if target.is_empty() {
        return Json(
            json!({"status":"error","message":"RULES_URL or url query parameter required"}),
        );
    }
    match fetch_text(&target, true).await {
        Ok(content) => Json(json!({"status":"success","url":target,"content":content})),
        Err(message) => Json(json!({"status":"error","url":target,"message":message,"content":""})),
    }
}

async fn reload_waf(
    State(state): State<EdgeState>,
    Json(payload): Json<WafRules>,
) -> Json<serde_json::Value> {
    record_security_event(
        state.pg.as_deref(),
        "waf_rules_reload_requested",
        "edge-ops",
        json!({"rule_count": payload.rules.len()}),
    )
    .await;
    Json(json!({"status":"queued","rule_count":payload.rules.len()}))
}

async fn purge_cdn(Json(payload): Json<PathsRequest>) -> Json<serde_json::Value> {
    let endpoint = env_string("CDN_PURGE_URL", "");
    if endpoint.is_empty() {
        return Json(json!({"status":"queued","provider":"local","paths":payload.paths}));
    }
    let response = reqwest::Client::new()
        .post(endpoint)
        .json(&json!({"paths": payload.paths}))
        .send()
        .await;
    match response {
        Ok(response) => Json(
            json!({"status": if response.status().is_success() { "success" } else { "error" }, "upstream_status": response.status().as_u16()}),
        ),
        Err(exc) => Json(json!({"status":"error","message":exc.to_string()})),
    }
}

async fn tls_status() -> Json<serde_json::Value> {
    Json(json!({
        "status":"ok",
        "managed": env_string("TLS_MANAGER_MODE", "external"),
        "certificate_source": env_string("TLS_CERTIFICATE_SOURCE", "deployment")
    }))
}

async fn ddos_status(State(state): State<EdgeState>) -> Json<serde_json::Value> {
    let stats = state.blocklist.stats().await;
    Json(json!({
        "status":"ok",
        "blocked_count": stats.blocked_count,
        "flagged_count": stats.flagged_count,
        "mode": env_string("DDOS_PROTECTION_MODE", "threshold")
    }))
}

async fn sync_blocklist(
    State(state): State<EdgeState>,
    Json(payload): Json<SyncRequest>,
) -> Json<serde_json::Value> {
    for ip in &payload.ips {
        state.blocklist.block(ip.clone()).await;
    }
    record_security_event(
        state.pg.as_deref(),
        "blocklist_sync_applied",
        payload.source.as_deref().unwrap_or("edge-ops"),
        json!({"count":payload.ips.len()}),
    )
    .await;
    Json(json!({"status":"success","count":payload.ips.len()}))
}

async fn security_score(Query(query): Query<HashMap<String, String>>) -> Json<serde_json::Value> {
    let mut headers = HashMap::new();
    if let Some(accept) = query.get("accept") {
        headers.insert("accept".to_string(), accept.clone());
    }
    let metadata = RequestMetadata {
        ip: Some(
            query
                .get("ip")
                .cloned()
                .unwrap_or_else(|| "0.0.0.0".to_string()),
        ),
        method: Some(
            query
                .get("method")
                .cloned()
                .unwrap_or_else(|| "GET".to_string()),
        ),
        path: Some(
            query
                .get("path")
                .cloned()
                .unwrap_or_else(|| "/".to_string()),
        ),
        user_agent: Some(query.get("user_agent").cloned().unwrap_or_default()),
        referer: query.get("referer").cloned(),
        headers: Some(headers),
        ..Default::default()
    };
    let decision = decide(metadata, FrequencyFeatures::default(), 0.7, 0.82, 0.92);
    Json(json!({
        "status":"success",
        "score": decision.score,
        "action": decision.action,
        "reason": decision.reason
    }))
}

fn robots_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if !valid_url(&parsed, false) {
        return None;
    }
    Some(format!(
        "{}://{}/robots.txt",
        parsed.scheme(),
        parsed.host_str()?
    ))
}

async fn fetch_text(url: &str, require_https: bool) -> Result<String, String> {
    let parsed = Url::parse(url).map_err(|exc| exc.to_string())?;
    if !valid_url(&parsed, require_https) {
        return Err("URL failed SSRF validation".to_string());
    }
    let response = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .map_err(|exc| exc.to_string())?
        .get(parsed)
        .header("user-agent", "AI-Scraping-Defense-Rust/1.0")
        .send()
        .await
        .map_err(|exc| exc.to_string())?;
    if response.status().is_redirection() {
        return Err("redirects are not followed".to_string());
    }
    response.text().await.map_err(|exc| exc.to_string())
}

fn valid_url(url: &Url, require_https: bool) -> bool {
    if require_https && url.scheme() != "https" {
        return false;
    }
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ip) => !ip.is_loopback() && !ip.is_private() && !ip.is_unspecified(),
            IpAddr::V6(ip) => !ip.is_loopback() && !ip.is_unique_local() && !ip.is_unspecified(),
        };
    }
    let allowed = env_string("EDGE_ALLOWED_DOMAINS", "");
    allowed.is_empty()
        || allowed
            .split(',')
            .map(str::trim)
            .any(|domain| !domain.is_empty() && host.ends_with(domain))
}

fn default_robots() -> &'static str {
    "User-agent: *\nDisallow: /"
}
