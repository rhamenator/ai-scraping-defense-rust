use asd_core::{health, observability_router, pg_connect_from_env, serve, ServiceConfig};
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    pg: Option<Arc<tokio_postgres::Client>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("tarpit-api", 8003);
    let state = AppState {
        pg: pg_connect_from_env().await.map(Arc::new),
    };
    let app = Router::new()
        .route("/health", get(|| async { health("tarpit-api").await }))
        .route("/", get(root))
        .route("/tarpit/*path", get(tarpit))
        .route("/assets/fake.js", get(fake_js))
        .merge(observability_router("tarpit-api"))
        .with_state(state);
    serve(app, config).await
}

async fn root() -> impl IntoResponse {
    Html("<html><body><h1>AI Scraping Defense Rust Tarpit</h1></body></html>")
}

async fn tarpit(State(state): State<AppState>, Path(path): Path<String>) -> impl IntoResponse {
    let content = markov_content(state.pg.as_deref()).await;
    Html(asd_tarpit::generate_page_with_content(Some(&path), content))
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
