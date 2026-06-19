use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

const KNOWN_BAD_UAS: &[&str] = &[
    "python-requests",
    "scrapy",
    "curl",
    "wget",
    "httpclient",
    "masscan",
    "nikto",
    "sqlmap",
    "bot",
    "crawler",
];

const KNOWN_BENIGN_CRAWLERS: &[&str] =
    &["googlebot", "bingbot", "duckduckbot", "slurp", "applebot"];

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RequestMetadata {
    pub ip: Option<String>,
    pub path: Option<String>,
    pub method: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub status: Option<u16>,
    pub bytes: Option<u64>,
    pub timestamp: Option<DateTime<Utc>>,
    pub headers: Option<HashMap<String, String>>,
    pub fingerprint_id: Option<String>,
    pub fingerprint_reuse_count: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct FrequencyFeatures {
    pub count: u64,
    pub time_since: f64,
}

impl Default for FrequencyFeatures {
    fn default() -> Self {
        Self {
            count: 0,
            time_since: -1.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtractedFeatures {
    pub country_code: String,
    pub ua_length: usize,
    pub status_code: u16,
    pub bytes_sent: u64,
    pub http_method: String,
    pub path_depth: usize,
    pub path_length: usize,
    pub path_is_root: u8,
    pub path_has_docs: u8,
    pub path_is_wp: u8,
    pub path_disallowed: u8,
    pub ua_is_known_bad: u8,
    pub ua_is_known_benign_crawler: u8,
    pub ua_is_empty: u8,
    pub ua_library_is_bot: u8,
    pub referer_is_empty: u8,
    pub referer_has_domain: u8,
    pub hour_of_day: i32,
    pub day_of_week: i32,
    pub request_frequency: u64,
    pub time_since_last_sec: f64,
    pub fingerprint_reuse_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub is_bot: bool,
    pub score: f64,
    pub action: String,
    pub reason: String,
    pub fingerprint: String,
    pub features: ExtractedFeatures,
}

pub fn extract_features(metadata: &RequestMetadata, freq: FrequencyFeatures) -> ExtractedFeatures {
    let ua = metadata.user_agent.as_deref().unwrap_or("");
    let ua_lower = ua.to_ascii_lowercase();
    let path = metadata.path.as_deref().unwrap_or("");
    let referer = metadata.referer.as_deref().unwrap_or("");
    let timestamp = metadata.timestamp.unwrap_or_else(Utc::now);

    ExtractedFeatures {
        country_code: String::new(),
        ua_length: ua.len(),
        status_code: metadata.status.unwrap_or_default(),
        bytes_sent: metadata.bytes.unwrap_or_default(),
        http_method: metadata
            .method
            .clone()
            .unwrap_or_else(|| "UNKNOWN".to_string()),
        path_depth: path.matches('/').count(),
        path_length: path.len(),
        path_is_root: u8::from(path == "/"),
        path_has_docs: u8::from(path.contains("/docs")),
        path_is_wp: u8::from(path.contains("/wp-") || path.contains("/xmlrpc.php")),
        path_disallowed: u8::from(is_disallowed_path(path)),
        ua_is_known_bad: u8::from(KNOWN_BAD_UAS.iter().any(|needle| ua_lower.contains(needle))),
        ua_is_known_benign_crawler: u8::from(
            KNOWN_BENIGN_CRAWLERS
                .iter()
                .any(|needle| ua_lower.contains(needle)),
        ),
        ua_is_empty: u8::from(ua.is_empty()),
        ua_library_is_bot: u8::from(ua_lower.contains("bot") || ua_lower.contains("crawler")),
        referer_is_empty: u8::from(referer.is_empty()),
        referer_has_domain: u8::from(
            referer.contains("://") && referer.split('/').nth(2).is_some(),
        ),
        hour_of_day: timestamp.hour() as i32,
        day_of_week: timestamp.weekday().num_days_from_monday() as i32,
        request_frequency: freq.count,
        time_since_last_sec: freq.time_since,
        fingerprint_reuse_count: metadata.fingerprint_reuse_count.unwrap_or(1),
    }
}

pub fn browser_fingerprint(metadata: &RequestMetadata) -> String {
    if let Some(id) = metadata.fingerprint_id.as_ref().filter(|id| !id.is_empty()) {
        return id.clone();
    }
    let empty = HashMap::new();
    let headers = metadata.headers.as_ref().unwrap_or(&empty);
    let parts = [
        metadata
            .user_agent
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase(),
        header(headers, "accept-language"),
        header(headers, "accept"),
        header(headers, "sec-ch-ua"),
        header(headers, "sec-fetch-site"),
    ];
    let raw = parts.join("|");
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn header(headers: &HashMap<String, String>, name: &str) -> String {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn score(features: &ExtractedFeatures) -> f64 {
    let mut score = 0.05;
    score += 0.30 * f64::from(features.ua_is_known_bad);
    score += 0.18 * f64::from(features.ua_is_empty);
    score += 0.12 * f64::from(features.path_disallowed);
    score += 0.10 * f64::from(features.path_is_wp);
    score += 0.06 * f64::from(features.referer_is_empty);
    score += (features.request_frequency as f64 / 100.0).min(0.18);
    if features.time_since_last_sec >= 0.0 && features.time_since_last_sec < 0.25 {
        score += 0.10;
    }
    if features.fingerprint_reuse_count > 5 {
        score += 0.10;
    }
    if features.ua_is_known_benign_crawler == 1 {
        score -= 0.25;
    }
    score.clamp(0.0, 1.0)
}

pub fn decide(
    metadata: RequestMetadata,
    freq: FrequencyFeatures,
    throttle_threshold: f64,
    tarpit_threshold: f64,
    block_threshold: f64,
) -> Decision {
    let fingerprint = browser_fingerprint(&metadata);
    let features = extract_features(&metadata, freq);
    let score = score(&features);
    let action = if score >= block_threshold {
        "block_ip"
    } else if score >= tarpit_threshold {
        "tarpit"
    } else if score >= throttle_threshold {
        "throttle"
    } else {
        "allow"
    };
    Decision {
        is_bot: score >= throttle_threshold,
        score,
        action: action.to_string(),
        reason: format!("Heuristic score {score:.2}"),
        fingerprint,
        features,
    }
}

fn is_disallowed_path(path: &str) -> bool {
    ["/admin", "/internal", "/.env", "/wp-admin", "/xmlrpc.php"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

#[derive(Clone, Default)]
pub struct InMemoryFrequency {
    inner: Arc<RwLock<HashMap<String, Vec<std::time::Instant>>>>,
}

impl InMemoryFrequency {
    pub async fn record(&self, key: &str, window: Duration) -> FrequencyFeatures {
        let now = std::time::Instant::now();
        let mut guard = self.inner.write().await;
        let entries = guard.entry(key.to_string()).or_default();
        entries.retain(|seen| now.duration_since(*seen) <= window);
        let previous = entries.last().copied();
        entries.push(now);
        FrequencyFeatures {
            count: entries.len().saturating_sub(1) as u64,
            time_since: previous
                .map(|seen| now.duration_since(seen).as_secs_f64())
                .unwrap_or(-1.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bad_ua_scores_as_bot() {
        let metadata = RequestMetadata {
            ip: Some("10.0.0.1".into()),
            path: Some("/wp-admin".into()),
            user_agent: Some("python-requests/2".into()),
            ..Default::default()
        };
        let decision = decide(
            metadata,
            FrequencyFeatures {
                count: 20,
                time_since: 0.1,
            },
            0.7,
            0.82,
            0.92,
        );
        assert!(decision.is_bot);
        assert!(decision.score > 0.7);
    }
}
