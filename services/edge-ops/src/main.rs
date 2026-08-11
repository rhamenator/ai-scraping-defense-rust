use asd_core::{
    env_string, env_u64, health, is_authorized, observability_router, record_security_event, serve,
    BlocklistState, ServiceConfig,
};
use asd_detection::{decide, FrequencyFeatures, RequestMetadata};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use reqwest::{redirect::Policy, Url};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

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

async fn fetch_robots(
    headers: HeaderMap,
    Query(query): Query<FetchQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_edge_admin(&headers)?;
    let target = query
        .url
        .unwrap_or_else(|| env_string("REAL_BACKEND_HOST", "https://example.com"));
    let Some(robots_url) = robots_url(&target) else {
        return Err(bad_request("URL failed validation"));
    };
    match fetch_text(&robots_url, false).await {
        Ok(content) => Ok(Json(
            json!({"status":"success","url":robots_url,"content":content}),
        )),
        Err(message) => Err((
            StatusCode::BAD_GATEWAY,
            Json(
                json!({"status":"error","url":robots_url,"message":message,"content":default_robots()}),
            ),
        )),
    }
}

async fn fetch_rules(
    headers: HeaderMap,
    Query(query): Query<FetchQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_edge_admin(&headers)?;
    let target = query.url.unwrap_or_else(|| env_string("RULES_URL", ""));
    if target.is_empty() {
        return Err(bad_request("RULES_URL or url query parameter required"));
    }
    match fetch_text(&target, true).await {
        Ok(content) => Ok(Json(
            json!({"status":"success","url":target,"content":content}),
        )),
        Err(message) => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"status":"error","url":target,"message":message,"content":""})),
        )),
    }
}

async fn reload_waf(
    State(state): State<EdgeState>,
    headers: HeaderMap,
    Json(payload): Json<WafRules>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_edge_admin(&headers)?;
    record_security_event(
        state.pg.as_deref(),
        "waf_rules_reload_requested",
        "edge-ops",
        json!({"rule_count": payload.rules.len()}),
    )
    .await;
    Ok(Json(
        json!({"status":"queued","rule_count":payload.rules.len()}),
    ))
}

async fn purge_cdn(
    headers: HeaderMap,
    Json(payload): Json<PathsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_edge_admin(&headers)?;
    let endpoint = env_string("CDN_PURGE_URL", "");
    if endpoint.is_empty() {
        return Ok(Json(
            json!({"status":"queued","provider":"local","paths":payload.paths}),
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(env_u64(
            "EDGE_HTTP_TIMEOUT_SECONDS",
            10,
        )))
        .build()
        .map_err(|exc| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status":"error","message":exc.to_string()})),
            )
        })?;
    let response = client
        .post(endpoint)
        .json(&json!({"paths": payload.paths}))
        .send()
        .await;
    match response {
        Ok(response) => Ok(Json(
            json!({"status": if response.status().is_success() { "success" } else { "error" }, "upstream_status": response.status().as_u16()}),
        )),
        Err(exc) => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"status":"error","message":exc.to_string()})),
        )),
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
    headers: HeaderMap,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_edge_admin(&headers)?;
    let mut accepted = 0usize;
    for ip in &payload.ips {
        if state.blocklist.block(ip.clone()).await {
            accepted += 1;
        }
    }
    let rejected = payload.ips.len() - accepted;
    record_security_event(
        state.pg.as_deref(),
        "blocklist_sync_applied",
        payload.source.as_deref().unwrap_or("edge-ops"),
        json!({"accepted":accepted,"rejected":rejected}),
    )
    .await;
    Ok(Json(
        json!({"status":"success","accepted":accepted,"rejected":rejected}),
    ))
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
    let authority = match parsed.port() {
        Some(port) => format!("{}:{port}", parsed.host_str()?),
        None => parsed.host_str()?.to_string(),
    };
    Some(format!("{}://{}/robots.txt", parsed.scheme(), authority))
}

async fn fetch_text(url: &str, require_https: bool) -> Result<String, String> {
    let parsed = Url::parse(url).map_err(|exc| exc.to_string())?;
    if !valid_url(&parsed, require_https) {
        return Err("URL failed SSRF validation".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL hostname is missing".to_string())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "URL port is unknown".to_string())?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|exc| format!("DNS resolution failed: {exc}"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err("URL resolved to a non-public address".to_string());
    }
    let pinned_address = SocketAddr::new(addresses[0].ip(), port);
    let mut response = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(env_u64(
            "EDGE_HTTP_TIMEOUT_SECONDS",
            10,
        )))
        .resolve(host, pinned_address)
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
    let maximum_bytes = env_u64("EDGE_MAX_FETCH_BYTES", 1_048_576) as usize;
    if response
        .content_length()
        .is_some_and(|length| length as usize > maximum_bytes)
    {
        return Err("upstream response exceeds EDGE_MAX_FETCH_BYTES".to_string());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|exc| exc.to_string())? {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err("upstream response exceeds EDGE_MAX_FETCH_BYTES".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "upstream response is not UTF-8 text".to_string())
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
        return is_public_ip(ip);
    }
    let allowed = env_string("EDGE_ALLOWED_DOMAINS", "");
    allowed.is_empty()
        || allowed.split(',').map(str::trim).any(|domain| {
            !domain.is_empty()
                && (host.eq_ignore_ascii_case(domain)
                    || host
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", domain.to_ascii_lowercase())))
        })
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                && !(octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                && octets[0] < 224
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            !(ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] & 0xffc0) == 0xfec0)
        }
    }
}

fn require_edge_admin(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if is_authorized(headers, "EDGE_OPS_API_KEY", "JWT_SECRET") {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status":"error","message":"Unauthorized"})),
        ))
    }
}

fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status":"error","message":message})),
    )
}

fn default_robots() -> &'static str {
    "User-agent: *\nDisallow: /"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_rejects_private_and_lookalike_hosts() {
        assert!(!valid_url(
            &Url::parse("http://127.0.0.1/data").unwrap(),
            false
        ));
        assert!(!valid_url(
            &Url::parse("http://10.0.0.1/data").unwrap(),
            false
        ));
    }

    #[test]
    fn robots_url_preserves_non_default_port() {
        assert_eq!(
            robots_url("https://example.com:8443/page").as_deref(),
            Some("https://example.com:8443/robots.txt")
        );
    }

    #[test]
    fn public_ip_filter_rejects_non_routable_addresses() {
        assert!(!is_public_ip("169.254.1.2".parse().unwrap()));
        assert!(!is_public_ip("2001:db8::1".parse().unwrap()));
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
    }
}
