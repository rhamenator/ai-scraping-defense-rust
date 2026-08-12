use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
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
    /// Validated JA3 value supplied by a trusted TLS collector or CDN adapter.
    pub tls_ja3: Option<String>,
    /// Validated canonical JA4 value supplied by a trusted TLS collector or CDN adapter.
    pub tls_ja4: Option<String>,
    pub tls_fingerprint_source: Option<String>,
    /// Set only after forward-confirmed reverse DNS or equivalent provider verification.
    pub verified_bot: Option<bool>,
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
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
    pub tls_fingerprint_source: Option<String>,
    pub features: ExtractedFeatures,
}

pub const MODEL_FEATURE_NAMES: [&str; 10] = [
    "ua_is_known_bad",
    "ua_is_empty",
    "ua_library_is_bot",
    "path_disallowed",
    "path_is_wp",
    "referer_is_empty",
    "ua_is_known_benign_crawler",
    "request_frequency",
    "rapid_repeat",
    "fingerprint_reuse_count",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrainedLinearModel {
    pub schema_version: u32,
    pub algorithm: String,
    pub feature_names: Vec<String>,
    pub weights: Vec<f64>,
    pub bias: f64,
}

impl TrainedLinearModel {
    pub fn validate(&self) -> Result<(), String> {
        let expected = MODEL_FEATURE_NAMES.map(str::to_string);
        if self.schema_version != 1
            || self.algorithm != "logistic_regression"
            || self.feature_names != expected
            || self.weights.len() != MODEL_FEATURE_NAMES.len()
            || !self.bias.is_finite()
            || self.weights.iter().any(|weight| !weight.is_finite())
        {
            return Err("unsupported or malformed detection model artifact".to_string());
        }
        Ok(())
    }

    pub fn predict(&self, features: &ExtractedFeatures) -> f64 {
        let linear = self
            .weights
            .iter()
            .zip(model_feature_vector(features))
            .fold(self.bias, |sum, (weight, feature)| sum + weight * feature);
        1.0 / (1.0 + (-linear.clamp(-40.0, 40.0)).exp())
    }
}

pub fn load_trained_model(path: impl AsRef<Path>) -> anyhow::Result<TrainedLinearModel> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    let model: TrainedLinearModel = serde_json::from_slice(&bytes)?;
    model
        .validate()
        .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
    Ok(model)
}

pub fn model_feature_vector(features: &ExtractedFeatures) -> [f64; 10] {
    [
        f64::from(features.ua_is_known_bad),
        f64::from(features.ua_is_empty),
        f64::from(features.ua_library_is_bot),
        f64::from(features.path_disallowed),
        f64::from(features.path_is_wp),
        f64::from(features.referer_is_empty),
        f64::from(features.ua_is_known_benign_crawler),
        (features.request_frequency as f64 / 100.0).min(1.0),
        f64::from(u8::from(
            features.time_since_last_sec >= 0.0 && features.time_since_last_sec < 0.25,
        )),
        (features.fingerprint_reuse_count as f64 / 10.0).min(1.0),
    ]
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
            metadata.verified_bot.unwrap_or(false)
                && KNOWN_BENIGN_CRAWLERS
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
        normalize_ja3(metadata.tls_ja3.as_deref()).unwrap_or_default(),
        normalize_ja4(metadata.tls_ja4.as_deref()).unwrap_or_default(),
    ];
    let raw = parts.join("|");
    hex::encode(Sha256::digest(raw.as_bytes()))
}

pub fn normalize_ja3(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    (candidate.len() == 32 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(candidate)
}

pub fn normalize_ja4(value: Option<&str>) -> Option<String> {
    let candidate = value?.trim().to_ascii_lowercase();
    let mut sections = candidate.split('_');
    let a = sections.next()?;
    let b = sections.next()?;
    let c = sections.next()?;
    if sections.next().is_some()
        || a.len() != 10
        || !a
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || b.len() != 12
        || c.len() != 12
        || !b
            .bytes()
            .chain(c.bytes())
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(candidate)
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
    decide_with_model(
        metadata,
        freq,
        throttle_threshold,
        tarpit_threshold,
        block_threshold,
        None,
    )
}

pub fn decide_with_model(
    metadata: RequestMetadata,
    freq: FrequencyFeatures,
    throttle_threshold: f64,
    tarpit_threshold: f64,
    block_threshold: f64,
    model: Option<&TrainedLinearModel>,
) -> Decision {
    let tls_ja3 = normalize_ja3(metadata.tls_ja3.as_deref());
    let tls_ja4 = normalize_ja4(metadata.tls_ja4.as_deref());
    let tls_fingerprint_source = (tls_ja3.is_some() || tls_ja4.is_some())
        .then(|| metadata.tls_fingerprint_source.clone())
        .flatten();
    let fingerprint = browser_fingerprint(&metadata);
    let features = extract_features(&metadata, freq);
    let score = model
        .map(|trained| trained.predict(&features))
        .unwrap_or_else(|| score(&features));
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
        reason: format!(
            "{} score {score:.2}",
            if model.is_some() {
                "Trained logistic-regression model"
            } else {
                "Heuristic"
            }
        ),
        fingerprint,
        tls_ja3,
        tls_ja4,
        tls_fingerprint_source,
        features,
    }
}

fn is_disallowed_path(path: &str) -> bool {
    ["/admin", "/internal", "/.env", "/wp-admin", "/xmlrpc.php"]
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

#[derive(Clone, Default)]
pub struct InMemoryFrequency {
    inner: Arc<RwLock<HashMap<String, Vec<std::time::Instant>>>>,
    operations: Arc<AtomicU64>,
}

impl InMemoryFrequency {
    pub async fn record(&self, key: &str, window: Duration) -> FrequencyFeatures {
        let now = std::time::Instant::now();
        let mut guard = self.inner.write().await;
        if self.operations.fetch_add(1, Ordering::Relaxed) % 1024 == 0 {
            guard.retain(|_, seen| {
                seen.retain(|entry| now.duration_since(*entry) <= window);
                !seen.is_empty()
            });
        }
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

    #[test]
    fn claimed_googlebot_is_not_trusted_without_verification() {
        let unverified = extract_features(
            &RequestMetadata {
                user_agent: Some("Googlebot/2.1".into()),
                verified_bot: Some(false),
                ..Default::default()
            },
            FrequencyFeatures::default(),
        );
        let verified = extract_features(
            &RequestMetadata {
                user_agent: Some("Googlebot/2.1".into()),
                verified_bot: Some(true),
                ..Default::default()
            },
            FrequencyFeatures::default(),
        );

        assert_eq!(unverified.ua_is_known_benign_crawler, 0);
        assert_eq!(verified.ua_is_known_benign_crawler, 1);
    }

    #[test]
    fn disallowed_path_matching_respects_segment_boundaries() {
        assert!(is_disallowed_path("/admin"));
        assert!(is_disallowed_path("/admin/users"));
        assert!(!is_disallowed_path("/administrator"));
    }

    #[test]
    fn tls_fingerprints_are_validated_and_contribute_to_tracking_identity() {
        let metadata = RequestMetadata {
            user_agent: Some("Mozilla/5.0".into()),
            tls_ja3: Some("72A589DA586844D7F0818CE684948EEA".into()),
            tls_ja4: Some("T13D1516H2_8DAAF6152771_E5627EFA2AB1".into()),
            tls_fingerprint_source: Some("envoy".into()),
            ..Default::default()
        };
        let decision = decide(
            metadata.clone(),
            FrequencyFeatures::default(),
            0.7,
            0.82,
            0.92,
        );

        assert_eq!(
            decision.tls_ja3.as_deref(),
            Some("72a589da586844d7f0818ce684948eea")
        );
        assert_eq!(
            decision.tls_ja4.as_deref(),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1")
        );
        assert_eq!(decision.tls_fingerprint_source.as_deref(), Some("envoy"));

        let mut without_tls = metadata;
        without_tls.tls_ja3 = None;
        without_tls.tls_ja4 = None;
        assert_ne!(browser_fingerprint(&without_tls), decision.fingerprint);
    }

    #[test]
    fn malformed_tls_fingerprints_are_discarded() {
        let decision = decide(
            RequestMetadata {
                tls_ja3: Some("not-a-ja3".into()),
                tls_ja4: Some("not-a-ja4".into()),
                tls_fingerprint_source: Some("untrusted".into()),
                ..Default::default()
            },
            FrequencyFeatures::default(),
            0.7,
            0.82,
            0.92,
        );
        assert!(decision.tls_ja3.is_none());
        assert!(decision.tls_ja4.is_none());
        assert!(decision.tls_fingerprint_source.is_none());
    }

    #[test]
    fn trained_model_can_override_the_fixed_heuristic_score() {
        let model = TrainedLinearModel {
            schema_version: 1,
            algorithm: "logistic_regression".into(),
            feature_names: MODEL_FEATURE_NAMES.map(str::to_string).to_vec(),
            weights: vec![0.0; MODEL_FEATURE_NAMES.len()],
            bias: 5.0,
        };
        let decision = decide_with_model(
            RequestMetadata {
                path: Some("/".into()),
                user_agent: Some("Mozilla/5.0".into()),
                ..Default::default()
            },
            FrequencyFeatures::default(),
            0.7,
            0.82,
            0.92,
            Some(&model),
        );

        assert!(decision.score > 0.99);
        assert_eq!(decision.action, "block_ip");
        assert!(decision
            .reason
            .starts_with("Trained logistic-regression model"));
    }
}
