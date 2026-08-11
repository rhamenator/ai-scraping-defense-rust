use asd_core::{
    env_f64, env_string, env_u64, health, is_authorized, observability_router, pg_connect_from_env,
    serve, ServiceConfig,
};
use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::Response,
    routing::{any, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
struct CrawlState {
    crawlers: Arc<RwLock<HashMap<String, Crawler>>>,
    pg: Option<Arc<tokio_postgres::Client>>,
}

#[derive(Clone, serde::Serialize)]
struct Crawler {
    name: String,
    token: String,
    purpose: String,
    credit: f64,
}

#[derive(Deserialize)]
struct CrawlerRegistration {
    name: String,
    token: Option<String>,
    purpose: String,
}

#[derive(Deserialize, serde::Serialize)]
struct Payment {
    token: String,
    amount: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("pay-per-crawl", 8012);
    let state = CrawlState {
        crawlers: Arc::default(),
        pg: pg_connect_from_env().await.map(Arc::new),
    };
    ensure_crawler_table(state.pg.as_deref()).await?;
    let app = Router::new()
        .route("/health", get(|| async { health("pay-per-crawl").await }))
        .route("/register-crawler", post(register))
        .route("/customers", post(register))
        .route("/pay", post(pay))
        .route("/charge", post(pay))
        .route("/refund", post(refund))
        .route("/balance/:token", get(balance))
        .route("/proxy/*path", any(proxy))
        .merge(observability_router("pay-per-crawl"))
        .with_state(state);
    serve(app, config).await
}

async fn register(
    State(state): State<CrawlState>,
    headers: HeaderMap,
    Json(registration): Json<CrawlerRegistration>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_payment_admin(&headers)?;
    let crawler = Crawler {
        name: registration.name,
        token: registration
            .token
            .filter(|token| !token.trim().is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        purpose: registration.purpose,
        credit: 0.0,
    };
    forward_gateway("create_customer", &crawler_gateway_payload(&crawler))
        .await
        .map_err(gateway_error)?;
    if let Some(pg) = state.pg.as_deref() {
        pg.execute(
            "INSERT INTO crawlers (token, name, purpose, credit)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (token) DO UPDATE
                 SET name = EXCLUDED.name, purpose = EXCLUDED.purpose",
            &[
                &crawler.token,
                &crawler.name,
                &crawler.purpose,
                &crawler.credit,
            ],
        )
        .await
        .map_err(|_| service_unavailable("crawler database unavailable"))?;
    }
    state
        .crawlers
        .write()
        .await
        .insert(crawler.token.clone(), crawler.clone());
    Ok(Json(json!({"status":"success","crawler":crawler})))
}

async fn pay(
    State(state): State<CrawlState>,
    headers: HeaderMap,
    Json(payment): Json<Payment>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_payment_admin(&headers)?;
    validate_payment(&payment)?;
    let gateway_url = env_string("PAYMENT_GATEWAY_URL", "");
    if !gateway_url.is_empty() {
        let provider = env_string("PAYMENT_PROVIDER", "generic-http").to_ascii_lowercase();
        if let Err(response) = forward_gateway(
            "charge",
            &payment_gateway_payload(&provider, "charge", &payment),
        )
        .await
        {
            return Err(gateway_error(response));
        }
    }
    if let Some(pg) = state.pg.as_deref() {
        let row = pg
            .query_opt(
                "UPDATE crawlers SET credit = credit + $1 WHERE token = $2 RETURNING credit",
                &[&payment.amount, &payment.token],
            )
            .await
            .map_err(|_| service_unavailable("crawler database unavailable"))?;
        if let Some(row) = row {
            let credit: f64 = row.get(0);
            if let Some(crawler) = state.crawlers.write().await.get_mut(&payment.token) {
                crawler.credit = credit;
            }
            return Ok(Json(
                json!({"status":"success","credit":credit,"store":"postgres"}),
            ));
        }
        return Err(not_found("unknown crawler"));
    }
    let mut guard = state.crawlers.write().await;
    if let Some(crawler) = guard.get_mut(&payment.token) {
        crawler.credit += payment.amount;
        Ok(Json(json!({"status":"success","credit":crawler.credit})))
    } else {
        Err(not_found("unknown crawler"))
    }
}

async fn refund(
    State(state): State<CrawlState>,
    headers: HeaderMap,
    Json(payment): Json<Payment>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_payment_admin(&headers)?;
    validate_payment(&payment)?;
    let provider = env_string("PAYMENT_PROVIDER", "generic-http").to_ascii_lowercase();
    if let Err(response) = forward_gateway(
        "refund",
        &payment_gateway_payload(&provider, "refund", &payment),
    )
    .await
    {
        return Err(gateway_error(response));
    }
    if let Some(pg) = state.pg.as_deref() {
        let row = pg
            .query_opt(
                "UPDATE crawlers SET credit = GREATEST(credit - $1, 0) WHERE token = $2 RETURNING credit",
                &[&payment.amount, &payment.token],
            )
            .await
            .map_err(|_| service_unavailable("crawler database unavailable"))?;
        if let Some(row) = row {
            let credit: f64 = row.get(0);
            if let Some(crawler) = state.crawlers.write().await.get_mut(&payment.token) {
                crawler.credit = credit;
            }
            return Ok(Json(
                json!({"status":"success","credit":credit,"store":"postgres"}),
            ));
        }
        return Err(not_found("unknown crawler"));
    }
    let mut guard = state.crawlers.write().await;
    if let Some(crawler) = guard.get_mut(&payment.token) {
        crawler.credit = (crawler.credit - payment.amount).max(0.0);
        Ok(Json(json!({"status":"success","credit":crawler.credit})))
    } else {
        Err(not_found("unknown crawler"))
    }
}

async fn balance(
    State(state): State<CrawlState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_payment_admin(&headers)?;
    if let Some(pg) = state.pg.as_deref() {
        let row = pg
            .query_opt("SELECT credit FROM crawlers WHERE token = $1", &[&token])
            .await
            .map_err(|_| service_unavailable("crawler database unavailable"))?;
        if let Some(row) = row {
            let credit: f64 = row.get(0);
            return Ok(Json(
                json!({"status":"success","credit":credit,"store":"postgres"}),
            ));
        }
        return Err(not_found("unknown crawler"));
    }
    let guard = state.crawlers.read().await;
    if let Some(crawler) = guard.get(&token) {
        Ok(Json(json!({"status":"success","credit":crawler.credit})))
    } else {
        Err(not_found("unknown crawler"))
    }
}

async fn proxy(
    State(state): State<CrawlState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let token = request
        .headers()
        .get("x-crawler-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if token.is_empty() {
        return Err(bad_request("x-crawler-token required"));
    }
    let charge = env_f64("PAY_PER_CRAWL_DEFAULT_CHARGE", 0.01);
    if !charge.is_finite() || charge <= 0.0 {
        return Err(service_unavailable("invalid server charge configuration"));
    }
    let backend = env_string("REAL_BACKEND_HOST", "");
    let backend_url = reqwest::Url::parse(&backend)
        .map_err(|_| service_unavailable("REAL_BACKEND_HOST must be a valid http(s) URL"))?;
    if !matches!(backend_url.scheme(), "http" | "https") {
        return Err(service_unavailable(
            "REAL_BACKEND_HOST must use http or https",
        ));
    }
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| service_unavailable("failed to initialize upstream HTTP client"))?;

    let (credit, store) = if let Some(pg) = state.pg.as_deref() {
        match pg
            .query_opt(
                "UPDATE crawlers
                 SET credit = credit - $1
                 WHERE token = $2 AND credit >= $1
                 RETURNING credit",
                &[&charge, &token],
            )
            .await
        {
            Ok(Some(row)) => {
                let credit: f64 = row.get(0);
                if let Some(crawler) = state.crawlers.write().await.get_mut(&token) {
                    crawler.credit = credit;
                }
                (credit, "postgres")
            }
            Ok(None) => {
                return Err(payment_required("insufficient credit or unknown crawler"));
            }
            Err(_) => {
                return Err(service_unavailable("crawler database unavailable"));
            }
        }
    } else {
        let mut guard = state.crawlers.write().await;
        match guard.get_mut(&token) {
            Some(crawler) if crawler.credit >= charge => {
                crawler.credit -= charge;
                (crawler.credit, "memory")
            }
            _ => {
                return Err(payment_required("insufficient credit or unknown crawler"));
            }
        }
    };

    let query = request
        .uri()
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    let target = format!(
        "{}/{}{}",
        backend.trim_end_matches('/'),
        path.trim_start_matches('/'),
        query
    );
    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .map_err(|_| bad_request("unsupported HTTP method"))?;
    let request_headers = request.headers().clone();
    let max_body_bytes = env_u64("PAY_PER_CRAWL_MAX_BODY_BYTES", 10 * 1024 * 1024) as usize;
    let body = match to_bytes(request.into_body(), max_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            restore_credit(&state, &token, charge).await;
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"status":"error","message":"request body exceeds configured limit"})),
            ));
        }
    };

    let mut outbound = client.request(method, target).body(body);
    for (name, value) in &request_headers {
        if is_forwardable_request_header(name.as_str()) {
            outbound = outbound.header(name, value);
        }
    }
    let mut upstream = match outbound.send().await {
        Ok(response) => response,
        Err(exc) => {
            restore_credit(&state, &token, charge).await;
            tracing::warn!(error = %exc, path = %path, "pay-per-crawl upstream request failed; credit restored");
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(
                    json!({"status":"error","message":"upstream request failed; charge restored"}),
                ),
            ));
        }
    };
    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let max_response_bytes = env_u64("PAY_PER_CRAWL_MAX_RESPONSE_BYTES", 10 * 1024 * 1024) as usize;
    if upstream
        .content_length()
        .is_some_and(|length| length as usize > max_response_bytes)
    {
        restore_credit(&state, &token, charge).await;
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(
                json!({"status":"error","message":"upstream response exceeds configured limit; charge restored"}),
            ),
        ));
    }
    let mut response_body = Vec::new();
    loop {
        let chunk = match upstream.chunk().await {
            Ok(chunk) => chunk,
            Err(exc) => {
                restore_credit(&state, &token, charge).await;
                tracing::warn!(error = %exc, "failed to read pay-per-crawl upstream response; credit restored");
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(
                        json!({"status":"error","message":"failed to read upstream response; charge restored"}),
                    ),
                ));
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        if response_body.len().saturating_add(chunk.len()) > max_response_bytes {
            restore_credit(&state, &token, charge).await;
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(
                    json!({"status":"error","message":"upstream response exceeds configured limit; charge restored"}),
                ),
            ));
        }
        response_body.extend_from_slice(&chunk);
    }
    let mut response = Response::builder()
        .status(status)
        .header("x-pay-per-crawl-charge", charge.to_string())
        .header("x-pay-per-crawl-credit", credit.to_string())
        .header("x-pay-per-crawl-store", store);
    for (name, value) in &upstream_headers {
        if !is_hop_by_hop(name.as_str()) && name != header::CONTENT_LENGTH {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from(response_body))
        .map_err(|_| service_unavailable("failed to construct upstream response"))
}

async fn restore_credit(state: &CrawlState, token: &str, amount: f64) {
    if let Some(pg) = state.pg.as_deref() {
        match pg
            .query_opt(
                "UPDATE crawlers SET credit = credit + $1 WHERE token = $2 RETURNING credit",
                &[&amount, &token],
            )
            .await
        {
            Ok(Some(row)) => {
                let credit: f64 = row.get(0);
                if let Some(crawler) = state.crawlers.write().await.get_mut(token) {
                    crawler.credit = credit;
                }
            }
            Ok(None) => tracing::error!(token, "failed to restore charge for unknown crawler"),
            Err(exc) => tracing::error!(error = %exc, token, "failed to restore crawler charge"),
        }
    } else if let Some(crawler) = state.crawlers.write().await.get_mut(token) {
        crawler.credit += amount;
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_forwardable_request_header(name: &str) -> bool {
    !is_hop_by_hop(name)
        && !name.eq_ignore_ascii_case(header::HOST.as_str())
        && !name.eq_ignore_ascii_case("x-crawler-token")
}

async fn forward_gateway(
    action: &str,
    payload: &serde_json::Value,
) -> Result<(), Json<serde_json::Value>> {
    let gateway_url = env_string("PAYMENT_GATEWAY_URL", "");
    if gateway_url.is_empty() {
        return Ok(());
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(exc) => {
            return Err(Json(json!({"status":"error","message":exc.to_string()})));
        }
    };
    let mut request = client
        .post(format!("{}/{}", gateway_url.trim_end_matches('/'), action))
        .json(payload);
    let api_key = env_string("PAYMENT_API_KEY", "");
    if !api_key.is_empty() {
        request = request.bearer_auth(api_key);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => Err(Json(json!({
            "status":"error",
            "message":"payment gateway rejected request",
            "operation": action,
            "upstream_status": response.status().as_u16()
        }))),
        Err(exc) => Err(Json(json!({
            "status":"error",
            "message":"payment gateway unavailable",
            "operation": action,
            "detail": exc.to_string()
        }))),
    }
}

fn require_payment_admin(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if is_authorized(headers, "PAY_PER_CRAWL_API_KEY", "JWT_SECRET") {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status":"error","message":"Unauthorized"})),
        ))
    }
}

fn validate_payment(payment: &Payment) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if payment.token.trim().is_empty() || !payment.amount.is_finite() || payment.amount <= 0.0 {
        Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({"status":"error","message":"token and a positive finite amount are required"}),
            ),
        ))
    } else {
        Ok(())
    }
}

fn gateway_error(response: Json<serde_json::Value>) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_GATEWAY, response)
}

fn service_unavailable(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"status":"error","message":message})),
    )
}

fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status":"error","message":message})),
    )
}

fn payment_required(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::PAYMENT_REQUIRED,
        Json(json!({"status":"error","message":message})),
    )
}

fn not_found(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"status":"error","message":message})),
    )
}

fn crawler_gateway_payload(crawler: &Crawler) -> serde_json::Value {
    json!({
        "token": crawler.token,
        "name": crawler.name,
        "purpose": crawler.purpose
    })
}

fn payment_gateway_payload(
    provider: &str,
    operation: &str,
    payment: &Payment,
) -> serde_json::Value {
    match provider {
        "stripe" | "stripe-compatible" => json!({
            "metadata": {"crawler_token": payment.token},
            "amount": (payment.amount * 100.0).round() as i64,
            "currency": env_string("PAYMENT_CURRENCY", "usd"),
            "capture_method": "automatic",
            "operation": operation
        }),
        "paypal" | "paypal-compatible" => json!({
            "intent": if operation == "refund" { "REFUND" } else { "CAPTURE" },
            "purchase_units": [{
                "reference_id": payment.token,
                "amount": {
                    "currency_code": env_string("PAYMENT_CURRENCY", "USD").to_ascii_uppercase(),
                    "value": format!("{:.2}", payment.amount)
                }
            }]
        }),
        "braintree" | "braintree-compatible" => json!({
            "customer_id": payment.token,
            "amount": format!("{:.2}", payment.amount),
            "operation": operation
        }),
        "square" | "square-compatible" => json!({
            "idempotency_key": uuid::Uuid::new_v4().to_string(),
            "source_id": payment.token,
            "amount_money": {
                "amount": (payment.amount * 100.0).round() as i64,
                "currency": env_string("PAYMENT_CURRENCY", "USD").to_ascii_uppercase()
            },
            "operation": operation
        }),
        "adyen" | "adyen-compatible" => json!({
            "reference": payment.token,
            "amount": {
                "currency": env_string("PAYMENT_CURRENCY", "USD").to_ascii_uppercase(),
                "value": (payment.amount * 100.0).round() as i64
            },
            "operation": operation
        }),
        "authorizenet" | "authorize_net" | "authorize.net" => json!({
            "createTransactionRequest": {
                "transactionRequest": {
                    "transactionType": if operation == "refund" { "refundTransaction" } else { "authCaptureTransaction" },
                    "amount": format!("{:.2}", payment.amount),
                    "refTransId": payment.token
                }
            }
        }),
        "credit-ledger" | "internal-ledger" => json!({
            "account": payment.token,
            "credit_delta": if operation == "refund" { -payment.amount } else { payment.amount },
            "source": "pay-per-crawl"
        }),
        _ => json!({
            "token": payment.token,
            "amount": payment.amount,
            "provider": provider
        }),
    }
}

async fn ensure_crawler_table(pg: Option<&tokio_postgres::Client>) -> anyhow::Result<()> {
    let Some(pg) = pg else {
        return Ok(());
    };
    pg.execute(
        "CREATE TABLE IF NOT EXISTS crawlers (
                token TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                purpose TEXT NOT NULL,
                credit DOUBLE PRECISION NOT NULL DEFAULT 0,
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

    #[test]
    fn crawler_token_and_hop_headers_are_not_forwardable() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(is_forwardable_request_header("authorization"));
        assert!(!is_forwardable_request_header("x-crawler-token"));
        assert!(!is_forwardable_request_header("host"));
    }

    #[test]
    fn payment_validation_rejects_non_finite_amounts() {
        assert!(validate_payment(&Payment {
            token: "crawler".into(),
            amount: f64::NAN,
        })
        .is_err());
        assert!(validate_payment(&Payment {
            token: "crawler".into(),
            amount: f64::INFINITY,
        })
        .is_err());
    }
}
