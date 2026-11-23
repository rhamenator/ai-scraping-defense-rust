use crate::{AppState, AuthVia};
use asd_core::env_string;
use axum::{
    extract::{Extension, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

pub type SetupStore = Arc<Mutex<SetupState>>;

#[derive(Debug, Clone, Serialize)]
pub struct SetupState {
    pub completed: bool,
    pub backend_url: String,
    pub model_uri: String,
    pub captcha_provider: String,
    pub cloudflare_enabled: bool,
    pub enable_mcp_model: bool,
    pub updated_at: Option<String>,
}

impl SetupState {
    pub fn from_env() -> Self {
        Self {
            completed: env_string("ADMIN_UI_SKIP_SETUP_WIZARD", "false")
                .eq_ignore_ascii_case("true"),
            backend_url: env_string("REAL_BACKEND_HOST", ""),
            model_uri: env_string("MODEL_URI", ""),
            captcha_provider: env_string("CAPTCHA_PROVIDER", "builtin"),
            cloudflare_enabled: env_string("CLOUDFLARE_ENABLED", "false")
                .eq_ignore_ascii_case("true"),
            enable_mcp_model: env_string("ENABLE_MCP_MODEL", "false")
                .eq_ignore_ascii_case("true"),
            updated_at: None,
        }
    }
}

pub fn new_setup_store() -> SetupStore {
    Arc::new(Mutex::new(SetupState::from_env()))
}

#[derive(Debug, Deserialize)]
pub struct SetupUpdateRequest {
    pub backend_url: Option<String>,
    pub model_uri: Option<String>,
    pub captcha_provider: Option<String>,
    pub cloudflare_enabled: Option<bool>,
    pub enable_mcp_model: Option<bool>,
    pub mark_complete: Option<bool>,
}

fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn validate_backend_url(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let valid_scheme = trimmed.starts_with("http://") || trimmed.starts_with("https://");
    if !valid_scheme || trimmed.contains(char::is_whitespace) {
        return Err("backend_url must be a valid http or https URL");
    }
    Ok(trimmed.to_string())
}

fn validate_captcha_provider(raw: &str) -> Result<String, &'static str> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "builtin" | "recaptcha" | "turnstile" => Ok(normalized),
        _ => Err("captcha_provider must be builtin, recaptcha, or turnstile"),
    }
}

fn render_setup_html(state: &SetupState) -> String {
    let backend = html_escape(&state.backend_url);
    let model = html_escape(&state.model_uri);
    let cf_selected = if state.cloudflare_enabled { "checked" } else { "" };
    let mcp_selected = if state.enable_mcp_model { "checked" } else { "" };
    let status_text = if state.completed {
        "Completed (authenticated admins can re-run setup anytime)"
    } else {
        "Incomplete"
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Setup Wizard - AI Scraping Defense</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }}
.card {{ max-width: 720px; margin: 0 auto; background: #1e293b; padding: 1.5rem 2rem; border-radius: 10px; }}
label {{ display: block; margin-top: 0.9rem; font-weight: 600; }}
input[type=text], select {{ width: 100%; box-sizing: border-box; padding: 0.5rem; margin-top: 0.25rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; }}
button {{ margin-top: 1.25rem; padding: 0.65rem 1.25rem; background: #2563eb; color: #fff; border: 0; border-radius: 6px; font-weight: 600; cursor: pointer; }}
a {{ color: #93c5fd; }}
</style>
</head>
<body>
<div class="card">
<h1>First-Run Setup Wizard</h1>
<p><a href="/">Dashboard</a> | <a href="/settings">Settings</a> | <a href="/logs">Logs</a> | <a href="/plugins">Plugins</a></p>
<p>Status: <strong>{status_text}</strong></p>
<form id="setup-form">
<label for="backend_url">Protected Backend URL (<code>REAL_BACKEND_HOST</code>)</label>
<input id="backend_url" name="backend_url" type="text" value="{backend}" placeholder="https://origin.example.com">
<label for="model_uri">Detection Model URI (<code>MODEL_URI</code>)</label>
<input id="model_uri" name="model_uri" type="text" value="{model}" placeholder="mcp://primary/classify">
<label for="captcha_provider">CAPTCHA Provider</label>
<select id="captcha_provider" name="captcha_provider">
<option value="builtin">builtin</option>
<option value="recaptcha">recaptcha</option>
<option value="turnstile">turnstile</option>
</select>
<label><input type="checkbox" id="cloudflare_enabled" {cf_selected}> Site Uses Cloudflare</label>
<label><input type="checkbox" id="enable_mcp_model" {mcp_selected}> Enable MCP Model Routing</label>
<label><input type="checkbox" id="mark_complete" checked> Mark first-run setup as complete</label>
<button type="submit">Save &amp; Complete Setup</button>
</form>
<p id="setup-status" role="status"></p>
<script>
document.getElementById('captcha_provider').value = '{provider}';
document.getElementById('setup-form').addEventListener('submit', async (ev) => {{
  ev.preventDefault();
  const res = await fetch('/setup', {{
    method: 'POST',
    credentials: 'same-origin',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      backend_url: document.getElementById('backend_url').value,
      model_uri: document.getElementById('model_uri').value,
      captcha_provider: document.getElementById('captcha_provider').value,
      cloudflare_enabled: document.getElementById('cloudflare_enabled').checked,
      enable_mcp_model: document.getElementById('enable_mcp_model').checked,
      mark_complete: document.getElementById('mark_complete').checked
    }})
  }});
  document.getElementById('setup-status').textContent = res.ok ? 'Setup saved.' : 'Failed to save setup.';
}});
</script>
</div>
</body>
</html>"#,
        provider = html_escape(&state.captcha_provider),
    )
}

pub async fn get_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    _auth: Extension<AuthVia>,
) -> Response {
    let snapshot = state.setup.lock().await.clone();
    let wants_html = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false);
    if wants_html {
        return Html(render_setup_html(&snapshot)).into_response();
    }
    Json(snapshot).into_response()
}

pub async fn post_setup(
    State(state): State<AppState>,
    _auth: Extension<AuthVia>,
    Json(payload): Json<SetupUpdateRequest>,
) -> Response {
    let mut guard = state.setup.lock().await;
    if let Some(raw_url) = payload.backend_url.as_deref() {
        match validate_backend_url(raw_url) {
            Ok(clean) => guard.backend_url = clean,
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
                    .into_response()
            }
        }
    }
    if let Some(model_uri) = payload.model_uri {
        guard.model_uri = model_uri.trim().to_string();
    }
    if let Some(raw_provider) = payload.captcha_provider.as_deref() {
        match validate_captcha_provider(raw_provider) {
            Ok(clean) => guard.captcha_provider = clean,
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
                    .into_response()
            }
        }
    }
    if let Some(cf) = payload.cloudflare_enabled {
        guard.cloudflare_enabled = cf;
    }
    if let Some(mcp) = payload.enable_mcp_model {
        guard.enable_mcp_model = mcp;
    }
    guard.completed = payload.mark_complete.unwrap_or(true);
    let epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    guard.updated_at = Some(epoch_secs.to_string());
    let updated = guard.clone();
    drop(guard);

    let _ = asd_core::record_security_event(
        &state.audit,
        "admin-ui",
        "setup_wizard_updated",
        serde_json::json!({ "completed": updated.completed }),
    )
    .await;
    Json(updated).into_response()
}
