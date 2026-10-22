use asd_core::{env_string, env_u64, health, observability_router, serve, ServiceConfig};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use sha2::Sha256;
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use tokio::sync::Mutex;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
struct CaptchaSolve {
    challenge_id: Option<String>,
    answer: Option<String>,
}

#[derive(Deserialize)]
struct CaptchaVerify {
    token: Option<String>,
}

#[derive(Clone)]
struct CaptchaState {
    secret: Arc<[u8]>,
    token_ttl_seconds: u64,
    issued: Arc<Mutex<HashMap<String, u64>>>,
    challenges: Arc<Mutex<HashMap<String, (String, u64)>>>,
}

impl CaptchaState {
    fn from_env() -> anyhow::Result<Self> {
        let configured = env_string("CAPTCHA_TOKEN_SECRET", "");
        anyhow::ensure!(
            configured.len() >= 32,
            "CAPTCHA_TOKEN_SECRET must contain at least 32 characters; run scripts/configure_credentials.py"
        );
        Ok(Self {
            secret: Arc::from(configured.into_bytes()),
            token_ttl_seconds: env_u64("CAPTCHA_TOKEN_TTL_SECONDS", 300).clamp(30, 3600),
            issued: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn issue_challenge(&self) -> (String, String) {
        let random = Uuid::new_v4();
        let bytes = random.as_bytes();
        let left = 2 + u16::from(bytes[0] % 8);
        let right = 2 + u16::from(bytes[1] % 8);
        let challenge_id = random.simple().to_string();
        let expires_at = unix_seconds().saturating_add(self.token_ttl_seconds);
        let mut challenges = self.challenges.lock().await;
        let now = unix_seconds();
        challenges.retain(|_, (_, expiry)| *expiry >= now);
        challenges.insert(
            challenge_id.clone(),
            ((left + right).to_string(), expires_at),
        );
        (challenge_id, format!("What is {left} + {right}?"))
    }

    async fn solve_challenge(&self, challenge_id: &str, answer: &str) -> bool {
        let Some((expected, expires_at)) = self.challenges.lock().await.remove(challenge_id) else {
            return false;
        };
        expires_at >= unix_seconds() && expected == answer.trim()
    }

    async fn issue(&self) -> String {
        let expires_at = unix_seconds().saturating_add(self.token_ttl_seconds);
        let nonce = Uuid::new_v4().simple().to_string();
        let payload = format!("{expires_at}.{nonce}");
        let signature = sign(&self.secret, payload.as_bytes());
        let mut issued = self.issued.lock().await;
        let now = unix_seconds();
        issued.retain(|_, expiry| *expiry >= now);
        issued.insert(nonce, expires_at);
        format!("{payload}.{signature}")
    }

    async fn verify_once(&self, token: &str) -> bool {
        let mut parts = token.split('.');
        let (Some(expiry), Some(nonce), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        let Ok(expires_at) = expiry.parse::<u64>() else {
            return false;
        };
        if expires_at < unix_seconds() || nonce.is_empty() {
            return false;
        }
        let payload = format!("{expiry}.{nonce}");
        let Ok(signature) = hex::decode(signature) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.secret) else {
            return false;
        };
        mac.update(payload.as_bytes());
        if mac.verify_slice(&signature).is_err() {
            return false;
        }
        self.issued.lock().await.remove(nonce) == Some(expires_at)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("captcha-service")?;
    let config = ServiceConfig::from_env("captcha-service", 8005);
    let app = Router::new()
        .route("/health", get(|| async { health("captcha-service").await }))
        .route("/challenge", get(challenge))
        .route("/solve", post(solve))
        .route("/verify", post(verify))
        .merge(observability_router("captcha-service"))
        .with_state(CaptchaState::from_env()?);
    serve(app, config).await
}

async fn challenge(State(state): State<CaptchaState>) -> Html<String> {
    let (challenge_id, question) = state.issue_challenge().await;
    Html(format!(
        r#"<html><body><form method="post" action="/solve"><label>{question}</label><input type="hidden" name="challenge_id" value="{challenge_id}"/><input name="answer" inputmode="numeric" autocomplete="off"/><button type="submit">Verify</button></form></body></html>"#,
    ))
}

async fn solve(
    State(state): State<CaptchaState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let payload: CaptchaSolve = decode_request(&headers, &body)?;
    let ok = match (payload.challenge_id.as_deref(), payload.answer.as_deref()) {
        (Some(challenge_id), Some(answer)) => state.solve_challenge(challenge_id, answer).await,
        _ => false,
    };
    let token = if ok { Some(state.issue().await) } else { None };
    Ok(Json(json!({"success": ok, "token": token})))
}

async fn verify(
    State(state): State<CaptchaState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let payload: CaptchaVerify = decode_request(&headers, &body)?;
    let success = match payload.token.as_deref() {
        Some(token) => state.verify_once(token).await,
        None => false,
    };
    Ok(Json(json!({"success": success})))
}

fn decode_request<T: DeserializeOwned>(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<T, (StatusCode, Json<serde_json::Value>)> {
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let result = if content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        serde_urlencoded::from_bytes(body).map_err(|error| error.to_string())
    } else {
        serde_json::from_slice(body).map_err(|error| error.to_string())
    };
    result.map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"status":"error","message":"Invalid payload"})),
        )
    })
}

fn sign(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn state() -> CaptchaState {
        CaptchaState {
            secret: Arc::from(b"integration-secret".as_slice()),
            token_ttl_seconds: 300,
            issued: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn browser_form_payload_is_accepted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let payload: CaptchaSolve = decode_request(&headers, b"challenge_id=abc&answer=7").unwrap();
        assert_eq!(payload.challenge_id.as_deref(), Some("abc"));
        assert_eq!(payload.answer.as_deref(), Some("7"));
    }

    #[test]
    fn malformed_payload_returns_bad_request() {
        let result = decode_request::<CaptchaSolve>(&HeaderMap::new(), b"not-json");
        assert!(matches!(result, Err((StatusCode::BAD_REQUEST, _))));
    }

    #[tokio::test]
    async fn issued_token_verifies_exactly_once() {
        let state = state();
        let token = state.issue().await;
        assert!(state.verify_once(&token).await);
        assert!(!state.verify_once(&token).await);
    }

    #[tokio::test]
    async fn arbitrary_nonempty_token_is_rejected() {
        assert!(!state().verify_once("anything").await);
    }

    #[tokio::test]
    async fn tampered_token_is_rejected_without_consuming_original() {
        let state = state();
        let token = state.issue().await;
        let mut tampered = token.clone();
        tampered.push('0');

        assert!(!state.verify_once(&tampered).await);
        assert!(state.verify_once(&token).await);
    }

    #[tokio::test]
    async fn wrong_solution_does_not_issue_token() {
        let state = state();
        let (challenge_id, _) = state.issue_challenge().await;
        let body = serde_json::to_vec(&json!({
            "challenge_id": challenge_id,
            "answer":"not-the-answer"
        }))
        .unwrap();
        let Json(response) = solve(State(state), HeaderMap::new(), Bytes::from(body))
            .await
            .expect("valid JSON should be accepted");

        assert_eq!(response["success"], false);
        assert!(response["token"].is_null());
    }

    #[tokio::test]
    async fn challenge_is_one_time_and_not_a_constant_answer() {
        let state = state();
        let (challenge_id, _) = state.issue_challenge().await;
        assert!(!state.solve_challenge(&challenge_id, "human").await);
        assert!(!state.solve_challenge(&challenge_id, "human").await);
    }
}
