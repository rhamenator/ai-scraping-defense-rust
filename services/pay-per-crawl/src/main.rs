use asd_core::{
    env_f64, env_string, health, observability_router, pg_connect_from_env, serve, ServiceConfig,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
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

#[derive(Clone, Deserialize, serde::Serialize)]
struct Crawler {
    name: String,
    token: String,
    purpose: String,
    credit: f64,
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
    ensure_crawler_table(state.pg.as_deref()).await;
    let app = Router::new()
        .route("/health", get(|| async { health("pay-per-crawl").await }))
        .route("/register-crawler", post(register))
        .route("/customers", post(register))
        .route("/pay", post(pay))
        .route("/charge", post(pay))
        .route("/refund", post(refund))
        .route("/balance/:token", get(balance))
        .route("/proxy/*path", get(proxy))
        .merge(observability_router("pay-per-crawl"))
        .with_state(state);
    serve(app, config).await
}

async fn register(
    State(state): State<CrawlState>,
    Json(crawler): Json<Crawler>,
) -> Json<serde_json::Value> {
    state
        .crawlers
        .write()
        .await
        .insert(crawler.token.clone(), crawler.clone());
    if let Some(pg) = state.pg.as_deref() {
        let _ = pg
            .execute(
                "INSERT INTO crawlers (token, name, purpose, credit)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (token) DO UPDATE
                 SET name = EXCLUDED.name, purpose = EXCLUDED.purpose, credit = EXCLUDED.credit",
                &[
                    &crawler.token,
                    &crawler.name,
                    &crawler.purpose,
                    &crawler.credit,
                ],
            )
            .await;
    }
    if let Err(response) =
        forward_gateway("create_customer", &crawler_gateway_payload(&crawler)).await
    {
        return response;
    }
    Json(json!({"status":"success","crawler":crawler}))
}

async fn pay(
    State(state): State<CrawlState>,
    Json(payment): Json<Payment>,
) -> Json<serde_json::Value> {
    let gateway_url = env_string("PAYMENT_GATEWAY_URL", "");
    if !gateway_url.is_empty() {
        let provider = env_string("PAYMENT_PROVIDER", "generic-http").to_ascii_lowercase();
        if let Err(response) = forward_gateway(
            "charge",
            &payment_gateway_payload(&provider, "charge", &payment),
        )
        .await
        {
            return response;
        }
    }
    if let Some(pg) = state.pg.as_deref() {
        if let Ok(Some(row)) = pg
            .query_opt(
                "UPDATE crawlers SET credit = credit + $1 WHERE token = $2 RETURNING credit",
                &[&payment.amount, &payment.token],
            )
            .await
        {
            let credit: f64 = row.get(0);
            return Json(json!({"status":"success","credit":credit,"store":"postgres"}));
        }
    }
    let mut guard = state.crawlers.write().await;
    if let Some(crawler) = guard.get_mut(&payment.token) {
        crawler.credit += payment.amount;
        Json(json!({"status":"success","credit":crawler.credit}))
    } else {
        Json(json!({"status":"error","message":"unknown crawler"}))
    }
}

async fn refund(
    State(state): State<CrawlState>,
    Json(payment): Json<Payment>,
) -> Json<serde_json::Value> {
    let provider = env_string("PAYMENT_PROVIDER", "generic-http").to_ascii_lowercase();
    if let Err(response) = forward_gateway(
        "refund",
        &payment_gateway_payload(&provider, "refund", &payment),
    )
    .await
    {
        return response;
    }
    if let Some(pg) = state.pg.as_deref() {
        if let Ok(Some(row)) = pg
            .query_opt(
                "UPDATE crawlers SET credit = GREATEST(credit - $1, 0) WHERE token = $2 RETURNING credit",
                &[&payment.amount, &payment.token],
            )
            .await
        {
            let credit: f64 = row.get(0);
            return Json(json!({"status":"success","credit":credit,"store":"postgres"}));
        }
    }
    let mut guard = state.crawlers.write().await;
    if let Some(crawler) = guard.get_mut(&payment.token) {
        crawler.credit = (crawler.credit - payment.amount).max(0.0);
        Json(json!({"status":"success","credit":crawler.credit}))
    } else {
        Json(json!({"status":"error","message":"unknown crawler"}))
    }
}

async fn balance(
    State(state): State<CrawlState>,
    Path(token): Path<String>,
) -> Json<serde_json::Value> {
    if let Some(pg) = state.pg.as_deref() {
        if let Ok(Some(row)) = pg
            .query_opt("SELECT credit FROM crawlers WHERE token = $1", &[&token])
            .await
        {
            let credit: f64 = row.get(0);
            return Json(json!({"status":"success","credit":credit,"store":"postgres"}));
        }
    }
    let guard = state.crawlers.read().await;
    if let Some(crawler) = guard.get(&token) {
        Json(json!({"status":"success","credit":crawler.credit}))
    } else {
        Json(json!({"status":"error","message":"unknown crawler"}))
    }
}

async fn proxy(
    State(state): State<CrawlState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Json<serde_json::Value> {
    let token = headers
        .get("x-crawler-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if token.is_empty() {
        return Json(json!({"status":"error","message":"x-crawler-token required"}));
    }
    let charge = env_f64("PAY_PER_CRAWL_DEFAULT_CHARGE", 0.01);
    if let Some(pg) = state.pg.as_deref() {
        if let Ok(Some(row)) = pg
            .query_opt(
                "UPDATE crawlers
                 SET credit = credit - $1
                 WHERE token = $2 AND credit >= $1
                 RETURNING credit",
                &[&charge, &token],
            )
            .await
        {
            let credit: f64 = row.get(0);
            return Json(
                json!({"status":"accepted","proxied_path":path,"charged":true,"credit":credit,"store":"postgres"}),
            );
        }
    }
    let mut guard = state.crawlers.write().await;
    if let Some(crawler) = guard.get_mut(token) {
        if crawler.credit >= charge {
            crawler.credit -= charge;
            return Json(
                json!({"status":"accepted","proxied_path":path,"charged":true,"credit":crawler.credit}),
            );
        }
    }
    Json(json!({"status":"error","message":"insufficient credit or unknown crawler"}))
}

async fn forward_gateway(
    action: &str,
    payload: &serde_json::Value,
) -> Result<(), Json<serde_json::Value>> {
    let gateway_url = env_string("PAYMENT_GATEWAY_URL", "");
    if gateway_url.is_empty() {
        return Ok(());
    }
    let mut request = reqwest::Client::new()
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

async fn ensure_crawler_table(pg: Option<&tokio_postgres::Client>) {
    let Some(pg) = pg else {
        return;
    };
    let _ = pg
        .execute(
            "CREATE TABLE IF NOT EXISTS crawlers (
                token TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                purpose TEXT NOT NULL,
                credit DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
            &[],
        )
        .await;
}
