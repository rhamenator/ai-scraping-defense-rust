use asd_core::{
    decode_hs256_jwt, env_string, health, is_authorized, load_security_events,
    observability_router, pg_connect_from_env, record_security_event, serve, BlocklistState,
    IpAction, ServiceConfig,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

type HmacSha1 = Hmac<sha1::Sha1>;

#[derive(Clone)]
struct AppState {
    config: ServiceConfig,
    blocklist: BlocklistState,
    pg: Option<Arc<tokio_postgres::Client>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    asd_core::init_tracing();
    let config = ServiceConfig::from_env("admin-ui", 8004);
    let state = AppState {
        config: config.clone(),
        blocklist: BlocklistState::from_env().await,
        pg: pg_connect_from_env().await.map(Arc::new),
    };
    ensure_admin_auth_tables(state.pg.as_deref()).await;
    let app = Router::new()
        .route("/health", get(|| async { health("admin-ui").await }))
        .route("/", get(index))
        .route("/settings", get(settings))
        .route("/logs", get(logs))
        .route("/plugins", get(plugins).post(update_plugins))
        .route("/metrics", get(metrics_json))
        .route("/block_stats", get(block_stats))
        .route("/blocklist", get(blocklist))
        .route("/block", post(block))
        .route("/unblock", post(unblock))
        .route("/passkey/register", post(passkey_register))
        .route("/passkey/login", post(passkey_login))
        .route("/webauthn/register/begin", post(webauthn_register_begin))
        .route(
            "/webauthn/register/complete",
            post(webauthn_register_complete),
        )
        .route("/webauthn/login/begin", post(webauthn_login_begin))
        .route("/webauthn/login/complete", post(webauthn_login_complete))
        .route("/mfa/totp/setup", post(mfa_totp_setup))
        .route("/mfa/totp/verify", post(mfa_totp_verify))
        .route("/mfa/backup-codes", post(mfa_backup_codes))
        .route("/mfa/backup-codes/remaining", get(mfa_remaining))
        .route("/mfa/backup-codes/verify", post(mfa_backup_code_verify))
        .route("/sso/user", get(sso_user))
        .route("/sso/validate", post(sso_user))
        .route("/logout", post(logout))
        .route("/gdpr/deletion-request", post(gdpr_deletion))
        .route("/gdpr/compliance-report", get(gdpr_report))
        .route("/operations/blocklist-sync", post(operation_blocklist_sync))
        .route("/operations/rules-fetch", post(operation_rules_fetch))
        .route("/operations/robots-fetch", post(operation_robots_fetch))
        .merge(observability_router("admin-ui"))
        .with_state(state);
    serve(app, config).await
}

async fn index() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Scraping Defense Admin</title>
  <style>
    :root { color-scheme: light dark; font-family: Arial, sans-serif; }
    body { margin: 0; background: #f7f8fa; color: #1f2933; }
    header { background: #1f2933; color: white; padding: 18px 24px; }
    main { max-width: 1040px; margin: 0 auto; padding: 24px; display: grid; gap: 18px; }
    section { background: white; border: 1px solid #dde3ea; border-radius: 6px; padding: 18px; }
    h1, h2 { margin: 0 0 12px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
    a { color: #0f766e; font-weight: 600; }
    code { background: #edf2f7; padding: 2px 5px; border-radius: 4px; }
  </style>
</head>
<body>
  <header>
    <h1>AI Scraping Defense Admin</h1>
  </header>
  <main>
    <section>
      <h2>Operations</h2>
      <div class="grid">
        <a href="/settings">Settings</a>
        <a href="/logs">Security events</a>
        <a href="/metrics">Metrics</a>
        <a href="/blocklist">Blocklist</a>
      </div>
    </section>
    <section>
      <h2>Identity</h2>
      <div class="grid">
        <a href="/sso/user">SSO user</a>
        <a href="/mfa/backup-codes/remaining">Backup-code count</a>
      </div>
    </section>
    <section>
      <h2>API Commands</h2>
      <p>Mutation routes accept <code>x-api-key</code> or Bearer JWT authorization.</p>
    </section>
  </main>
</body>
</html>"#,
    )
}

async fn settings(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "service": "admin-ui",
        "port": state.config.port,
        "mode": "rust"
    }))
}

async fn logs(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"entries": load_security_events(state.pg.as_deref(), 200).await}))
}

async fn plugins() -> Json<serde_json::Value> {
    Json(json!({"plugins":[],"dynamic_plugins":false}))
}

async fn metrics_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = state.blocklist.stats().await;
    Json(json!({
        "blocked_count": stats.blocked_count,
        "flagged_count": stats.flagged_count,
        "service": "admin-ui"
    }))
}

async fn update_plugins(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    record_security_event(
        state.pg.as_deref(),
        "admin_update_plugins",
        "admin",
        json!({"plugins":[]}),
    )
    .await;
    Ok(Json(json!({"status":"success","plugins":[]})))
}

async fn block_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::to_value(state.blocklist.stats().await).unwrap())
}

async fn blocklist(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"blocked": state.blocklist.blocked().await}))
}

async fn block(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(action): Json<IpAction>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    if let Some(ip) = action.ip {
        state.blocklist.block(ip.clone()).await;
        record_security_event(
            state.pg.as_deref(),
            "admin_block_ip",
            "admin",
            json!({"ip":ip,"reason":action.reason}),
        )
        .await;
        Ok(Json(json!({"status":"success","ip":ip})))
    } else {
        Ok(Json(json!({"status":"error","message":"ip required"})))
    }
}

async fn unblock(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(action): Json<IpAction>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    if let Some(ip) = action.ip {
        state.blocklist.allow(&ip).await;
        record_security_event(
            state.pg.as_deref(),
            "admin_unblock_ip",
            "admin",
            json!({"ip":ip}),
        )
        .await;
        Ok(Json(json!({"status":"success","ip":ip})))
    } else {
        Ok(Json(json!({"status":"error","message":"ip required"})))
    }
}

async fn gdpr_deletion(State(state): State<AppState>) -> Json<serde_json::Value> {
    record_security_event(
        state.pg.as_deref(),
        "gdpr_deletion_requested",
        "admin",
        json!({"processor":"ai-scraping-defense-rust"}),
    )
    .await;
    Json(json!({"status":"queued","request":"gdpr-deletion"}))
}

async fn gdpr_report() -> Json<serde_json::Value> {
    Json(json!({"status":"ok","processor":"ai-scraping-defense-rust","records":[]}))
}

async fn sso_user(
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !env_bool("ADMIN_UI_SSO_ENABLED", false) {
        return Ok(Json(json!({"status":"disabled"})));
    }
    match env_string("ADMIN_UI_SSO_MODE", "oidc")
        .to_ascii_lowercase()
        .as_str()
    {
        "saml" => saml_user(&headers),
        "oidc" => oidc_user(&headers),
        _ => Err(bad_request("unsupported SSO mode")),
    }
}

#[derive(Deserialize)]
struct UserRequest {
    user: Option<String>,
}

#[derive(Deserialize)]
struct CredentialRequest {
    user: Option<String>,
    challenge: Option<String>,
    credential_id: Option<String>,
    public_key: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct TotpVerifyRequest {
    user: Option<String>,
    code: String,
}

async fn passkey_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Option<Json<CredentialRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    let payload = payload
        .map(|Json(payload)| payload)
        .unwrap_or(CredentialRequest {
            user: None,
            challenge: None,
            credential_id: None,
            public_key: None,
        });
    let user = admin_user(payload.user);
    let credential_id = payload.credential_id.unwrap_or_else(|| random_token(16));
    let public_key = payload
        .public_key
        .unwrap_or_else(|| json!({"kind":"passkey"}));
    store_credential(state.pg.as_deref(), &user, &credential_id, public_key).await?;
    record_security_event(
        state.pg.as_deref(),
        "admin_passkey_registered",
        &user,
        json!({"credential_id":credential_id}),
    )
    .await;
    Ok(Json(json!({
        "status":"registered",
        "credential_id": credential_id,
        "user": user
    })))
}

async fn passkey_login(
    State(state): State<AppState>,
    payload: Option<Json<CredentialRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let payload = payload
        .map(|Json(payload)| payload)
        .unwrap_or(CredentialRequest {
            user: None,
            challenge: None,
            credential_id: None,
            public_key: None,
        });
    let user = admin_user(payload.user);
    let credential_id = payload.credential_id.unwrap_or_default();
    if credential_id.is_empty()
        || !credential_exists(state.pg.as_deref(), &user, &credential_id).await?
    {
        return Err(bad_request("known credential_id required"));
    }
    let token = issue_session(state.pg.as_deref(), &user).await?;
    Ok(Json(json!({"status":"success","token":token,"user":user})))
}

async fn webauthn_register_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Option<Json<UserRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    issue_challenge(state.pg.as_deref(), payload, "register").await
}

async fn webauthn_login_begin(
    State(state): State<AppState>,
    payload: Option<Json<UserRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    issue_challenge(state.pg.as_deref(), payload, "login").await
}

async fn webauthn_register_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CredentialRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    let user = admin_user(payload.user);
    let challenge = payload.challenge.unwrap_or_default();
    if !consume_challenge(state.pg.as_deref(), &user, "register", &challenge).await? {
        return Err(bad_request("valid registration challenge required"));
    }
    let credential_id = payload.credential_id.unwrap_or_else(|| random_token(16));
    let public_key = payload.public_key.unwrap_or_else(|| json!({}));
    store_credential(state.pg.as_deref(), &user, &credential_id, public_key).await?;
    record_security_event(
        state.pg.as_deref(),
        "admin_webauthn_registered",
        &user,
        json!({"credential_id":credential_id}),
    )
    .await;
    Ok(Json(
        json!({"status":"registered","credential_id":credential_id}),
    ))
}

async fn webauthn_login_complete(
    State(state): State<AppState>,
    Json(payload): Json<CredentialRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.user);
    let challenge = payload.challenge.unwrap_or_default();
    let credential_id = payload.credential_id.unwrap_or_default();
    if !consume_challenge(state.pg.as_deref(), &user, "login", &challenge).await? {
        return Err(bad_request("valid login challenge required"));
    }
    if !credential_exists(state.pg.as_deref(), &user, &credential_id).await? {
        return Err(bad_request("known credential_id required"));
    }
    let token = issue_session(state.pg.as_deref(), &user).await?;
    Ok(Json(json!({"status":"success","token":token,"user":user})))
}

async fn mfa_backup_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Option<Json<UserRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    let user = admin_user(payload.and_then(|Json(payload)| payload.user));
    let codes = (0..10).map(|_| random_token(4)).collect::<Vec<_>>();
    let hashes = codes
        .iter()
        .map(|code| hash_secret(code))
        .collect::<Vec<_>>();
    ensure_mfa_record(state.pg.as_deref(), &user).await?;
    store_backup_hashes(state.pg.as_deref(), &user, &hashes).await?;
    Ok(Json(
        json!({"status":"success","backup_codes":codes,"user":user}),
    ))
}

async fn mfa_remaining(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(None);
    let remaining = backup_hashes(state.pg.as_deref(), &user).await?.len();
    Ok(Json(json!({"remaining":remaining,"user":user})))
}

async fn mfa_totp_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Option<Json<UserRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET") {
        return Err(unauthorized());
    }
    let user = admin_user(payload.and_then(|Json(payload)| payload.user));
    let secret = ensure_mfa_record(state.pg.as_deref(), &user).await?;
    Ok(Json(json!({
        "status":"success",
        "user":user,
        "totp_secret":secret,
        "algorithm":"SHA1",
        "digits":6,
        "period":30
    })))
}

async fn mfa_totp_verify(
    State(state): State<AppState>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.user);
    let secret = ensure_mfa_record(state.pg.as_deref(), &user).await?;
    let valid = verify_totp(&secret, &payload.code);
    Ok(Json(
        json!({"status": if valid { "success" } else { "error" }, "valid": valid}),
    ))
}

async fn mfa_backup_code_verify(
    State(state): State<AppState>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.user);
    let hash = hash_secret(&payload.code);
    let mut hashes = backup_hashes(state.pg.as_deref(), &user).await?;
    let valid = hashes.iter().any(|existing| existing == &hash);
    if valid {
        hashes.retain(|existing| existing != &hash);
        store_backup_hashes(state.pg.as_deref(), &user, &hashes).await?;
    }
    Ok(Json(
        json!({"status": if valid { "success" } else { "error" }, "valid": valid, "remaining": hashes.len()}),
    ))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Json<serde_json::Value> {
    if let Some(token) = bearer_token(&headers) {
        if let Some(pg) = state.pg.as_deref() {
            let _ = pg
                .execute("DELETE FROM admin_sessions WHERE token = $1", &[&token])
                .await;
        }
    }
    Json(json!({"status":"success"}))
}

async fn operation_blocklist_sync(State(state): State<AppState>) -> Json<serde_json::Value> {
    operation_queued(state, "blocklist-sync").await
}

async fn operation_rules_fetch(State(state): State<AppState>) -> Json<serde_json::Value> {
    operation_queued(state, "rules-fetch").await
}

async fn operation_robots_fetch(State(state): State<AppState>) -> Json<serde_json::Value> {
    operation_queued(state, "robots-fetch").await
}

fn unauthorized() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"status":"error","message":"Unauthorized"})),
    )
}

fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status":"error","message":message})),
    )
}

fn storage_required() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(
            json!({"status":"error","message":"Postgres is required for persisted admin auth state"}),
        ),
    )
}

fn admin_user(user: Option<String>) -> String {
    user.filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("ADMIN_USERNAME").ok())
        .unwrap_or_else(|| "admin".to_string())
}

fn random_token(bytes: usize) -> String {
    let mut data = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut data);
    hex::encode(data)
}

fn hash_secret(value: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(value.as_bytes()))
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(ToString::to_string)
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn oidc_user(
    headers: &HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = bearer_token(headers).or_else(|| {
        let header = env_string("ADMIN_UI_SSO_TOKEN_HEADER", "X-SSO-Token");
        headers
            .get(header)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string)
    });
    let Some(token) = token else {
        return Err(unauthorized());
    };
    let secret = env_string("ADMIN_UI_OIDC_JWT_SECRET", "");
    if secret.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status":"error","message":"OIDC JWT secret not configured"})),
        ));
    }
    let Some(claims) = decode_hs256_jwt(&token, &secret) else {
        return Err(unauthorized());
    };
    let issuer = env_string("ADMIN_UI_OIDC_ISSUER", "");
    if !issuer.is_empty() && claims.get("iss").and_then(|value| value.as_str()) != Some(&issuer) {
        return Err(unauthorized());
    }
    let audience = env_string("ADMIN_UI_OIDC_AUDIENCE", "");
    if !audience.is_empty() && !claim_matches(&claims, "aud", &audience) {
        return Err(unauthorized());
    }
    let roles = claim_values(&claims, "roles")
        .into_iter()
        .chain(claim_values(&claims, "groups"))
        .collect::<Vec<_>>();
    let required_role = env_string("ADMIN_UI_OIDC_REQUIRED_ROLE", "");
    if !required_role.is_empty() && !roles.iter().any(|role| role == &required_role) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"status":"error","message":"Insufficient role"})),
        ));
    }
    let required_group = env_string("ADMIN_UI_OIDC_REQUIRED_GROUP", "");
    if !required_group.is_empty() && !roles.iter().any(|role| role == &required_group) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"status":"error","message":"Insufficient group"})),
        ));
    }
    let username = claims
        .get("preferred_username")
        .or_else(|| claims.get("email"))
        .or_else(|| claims.get("sub"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    Ok(Json(json!({
        "status":"success",
        "provider":"oidc",
        "username": username,
        "roles": roles
    })))
}

fn saml_user(
    headers: &HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user_header = env_string("ADMIN_UI_SAML_HEADER_USER", "X-SSO-User");
    let groups_header = env_string("ADMIN_UI_SAML_HEADER_GROUPS", "X-SSO-Groups");
    let username = headers
        .get(user_header)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(unauthorized)?;
    let groups = headers
        .get(groups_header)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let required_group = env_string("ADMIN_UI_SAML_REQUIRED_GROUP", "");
    if !required_group.is_empty() && !groups.iter().any(|group| group == &required_group) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"status":"error","message":"Insufficient group"})),
        ));
    }
    Ok(Json(json!({
        "status":"success",
        "provider":"saml",
        "username": username,
        "groups": groups
    })))
}

fn claim_matches(claims: &serde_json::Value, name: &str, expected: &str) -> bool {
    claims.get(name).is_some_and(|value| {
        value.as_str() == Some(expected)
            || value
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)))
    })
}

fn claim_values(claims: &serde_json::Value, name: &str) -> Vec<String> {
    match claims.get(name) {
        Some(value) if value.is_string() => value
            .as_str()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(value) if value.is_array() => value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item.as_str().map(ToString::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

async fn ensure_admin_auth_tables(pg: Option<&tokio_postgres::Client>) {
    let Some(pg) = pg else {
        return;
    };
    let _ = pg
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS admin_challenges (
                user_name TEXT NOT NULL,
                purpose TEXT NOT NULL,
                challenge TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (user_name, purpose)
            );
            CREATE TABLE IF NOT EXISTS admin_credentials (
                user_name TEXT NOT NULL,
                credential_id TEXT PRIMARY KEY,
                public_key JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS admin_mfa (
                user_name TEXT PRIMARY KEY,
                totp_secret TEXT NOT NULL,
                backup_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token TEXT PRIMARY KEY,
                user_name TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            );",
        )
        .await;
}

async fn issue_challenge(
    pg: Option<&tokio_postgres::Client>,
    payload: Option<Json<UserRequest>>,
    purpose: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.and_then(|Json(payload)| payload.user));
    let challenge = random_token(32);
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    pg.execute(
        "INSERT INTO admin_challenges (user_name, purpose, challenge, expires_at)
         VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes')
         ON CONFLICT (user_name, purpose) DO UPDATE
         SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at",
        &[&user, &purpose, &challenge],
    )
    .await
    .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(Json(
        json!({"status":"challenge_issued","challenge":challenge,"timeout":60000,"user":user}),
    ))
}

async fn consume_challenge(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
    purpose: &str,
    challenge: &str,
) -> Result<bool, (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    let row = pg
        .query_opt(
            "DELETE FROM admin_challenges
             WHERE user_name = $1 AND purpose = $2 AND challenge = $3 AND expires_at > NOW()
             RETURNING challenge",
            &[&user, &purpose, &challenge],
        )
        .await
        .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(row.is_some())
}

async fn store_credential(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
    credential_id: &str,
    public_key: serde_json::Value,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    pg.execute(
        "INSERT INTO admin_credentials (user_name, credential_id, public_key)
         VALUES ($1, $2, $3)
         ON CONFLICT (credential_id) DO UPDATE
         SET user_name = EXCLUDED.user_name, public_key = EXCLUDED.public_key",
        &[&user, &credential_id, &public_key],
    )
    .await
    .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(())
}

async fn credential_exists(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
    credential_id: &str,
) -> Result<bool, (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    let row = pg
        .query_opt(
            "SELECT 1 FROM admin_credentials WHERE user_name = $1 AND credential_id = $2",
            &[&user, &credential_id],
        )
        .await
        .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(row.is_some())
}

async fn issue_session(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    let token = random_token(32);
    pg.execute(
        "INSERT INTO admin_sessions (token, user_name, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '12 hours')",
        &[&token, &user],
    )
    .await
    .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(token)
}

async fn ensure_mfa_record(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    if let Some(row) = pg
        .query_opt(
            "SELECT totp_secret FROM admin_mfa WHERE user_name = $1",
            &[&user],
        )
        .await
        .map_err(|exc| internal_error(exc.to_string()))?
    {
        return Ok(row.get(0));
    }
    let secret = random_token(20);
    pg.execute(
        "INSERT INTO admin_mfa (user_name, totp_secret, backup_hashes)
         VALUES ($1, $2, '[]'::jsonb)
         ON CONFLICT (user_name) DO NOTHING",
        &[&user, &secret],
    )
    .await
    .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(secret)
}

async fn backup_hashes(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
) -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    let Some(row) = pg
        .query_opt(
            "SELECT backup_hashes FROM admin_mfa WHERE user_name = $1",
            &[&user],
        )
        .await
        .map_err(|exc| internal_error(exc.to_string()))?
    else {
        return Ok(Vec::new());
    };
    let value: serde_json::Value = row.get(0);
    Ok(serde_json::from_value(value).unwrap_or_default())
}

async fn store_backup_hashes(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
    hashes: &[String],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    let value = json!(hashes);
    pg.execute(
        "UPDATE admin_mfa SET backup_hashes = $2 WHERE user_name = $1",
        &[&user, &value],
    )
    .await
    .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(())
}

fn verify_totp(secret_hex: &str, code: &str) -> bool {
    let Ok(secret) = hex::decode(secret_hex) else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 30)
        .unwrap_or_default();
    (now.saturating_sub(1)..=now + 1).any(|counter| totp_code(&secret, counter) == code)
}

fn totp_code(secret: &[u8], counter: u64) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    format!("{:06}", binary % 1_000_000)
}

async fn operation_queued(state: AppState, operation: &str) -> Json<serde_json::Value> {
    record_security_event(
        state.pg.as_deref(),
        "admin_operation_queued",
        "admin",
        json!({"operation":operation}),
    )
    .await;
    Json(json!({"status":"queued","operation":operation}))
}

fn internal_error(message: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"status":"error","message":message})),
    )
}
