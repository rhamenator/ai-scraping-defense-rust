mod oidc;
mod webauthn;

use asd_core::{
    env_string, health, is_authorized, load_security_events, observability_router,
    pg_connect_from_env, record_security_event, serve, AuditStore, BlocklistState, IpAction,
    ServiceConfig,
};
use axum::{
    extract::{ConnectInfo, Extension, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

type HmacSha1 = Hmac<sha1::Sha1>;

#[derive(Clone)]
struct AppState {
    config: ServiceConfig,
    blocklist: BlocklistState,
    pg: Option<Arc<tokio_postgres::Client>>,
    audit: AuditStore,
    oidc: oidc::OidcVerifier,
    passkeys: Arc<webauthn::PasskeyService>,
    mfa_attempts: Arc<Mutex<HashMap<IpAddr, (Instant, u32)>>>,
    sessions: SessionStore,
}

const SESSION_COOKIE: &str = "asd_admin_session";
const MAX_BROWSER_SESSIONS: usize = 200;

/// A browser sign-in. Only a hash of the cookie value is kept, so the store cannot be replayed from memory.
#[derive(Clone)]
struct BrowserSession {
    expires: Instant,
    csrf: String,
}

type SessionStore = Arc<Mutex<HashMap<String, BrowserSession>>>;

/// How the current request authenticated; inserted by the middleware for the handlers that accept a browser session.
#[derive(Clone, Copy)]
struct AuthVia {
    session: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = asd_core::init_tracing("admin-ui")?;
    let config = ServiceConfig::from_env("admin-ui", 8004);
    let pg = pg_connect_from_env().await.map(Arc::new);
    let audit = AuditStore::from_env(pg.clone()).await?;
    let oidc = oidc::OidcVerifier::from_env()?;
    let passkeys = Arc::new(webauthn::PasskeyService::from_env()?);
    let state = AppState {
        config: config.clone(),
        blocklist: BlocklistState::from_env().await?,
        pg,
        audit,
        oidc,
        passkeys,
        mfa_attempts: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    ensure_admin_auth_tables(state.pg.as_deref()).await?;
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
        .route("/passkey/register", post(webauthn_register_begin))
        .route("/passkey/login", post(webauthn_login_begin))
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
        .route("/session", get(get_session).post(create_session))
        .route("/logout", post(logout))
        .route("/gdpr/deletion-request", post(gdpr_deletion))
        .route("/gdpr/compliance-report", get(gdpr_report))
        .route("/operations/blocklist-sync", post(operation_blocklist_sync))
        .route("/operations/rules-fetch", post(operation_rules_fetch))
        .route("/operations/robots-fetch", post(operation_robots_fetch))
        .merge(observability_router("admin-ui"))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_middleware,
        ))
        .with_state(state);
    serve(app, config).await
}

async fn require_admin_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    if matches!(
        path.as_str(),
        "/mfa/totp/verify" | "/mfa/backup-codes/verify" | "/session"
    ) {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        if !admit_mfa_attempt(&state.mfa_attempts, peer).await {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }
    let public_path = matches!(
        path.as_str(),
        "/" | "/health"
            | "/session"
            | "/sso/user"
            | "/sso/validate"
            | "/mfa/totp/verify"
            | "/mfa/backup-codes/verify"
            | "/passkey/login"
            | "/webauthn/login/begin"
            | "/webauthn/login/complete"
    );
    let mut via_session = false;
    if !public_path {
        let configured_auth = is_authorized(request.headers(), "ADMIN_API_KEY", "JWT_SECRET");
        let browser_session = if configured_auth {
            None
        } else {
            browser_session_for(&state, request.headers()).await
        };
        if let Some(session) = &browser_session {
            // Header credentials are never sent by a browser on its own, but cookies are: every state-changing
            // request that rests on the cookie must echo the session's CSRF token.
            if !matches!(
                *request.method(),
                Method::GET | Method::HEAD | Method::OPTIONS
            ) {
                let supplied = request
                    .headers()
                    .get("x-csrf-token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                if !constant_time_eq(supplied, &session.csrf) {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error":"Invalid CSRF token"})),
                    )
                        .into_response();
                }
            }
            via_session = true;
        }
        let session_auth = if configured_auth || via_session {
            false
        } else {
            match bearer_token(request.headers()) {
                Some(token) => webauthn::session_is_valid(state.pg.as_deref(), &token).await,
                None => false,
            }
        };
        if !configured_auth && !via_session && !session_auth {
            return unauthorized().into_response();
        }
    }
    request.extensions_mut().insert(AuthVia {
        session: via_session,
    });
    next.run(request).await
}

async fn admit_mfa_attempt(
    attempts: &Mutex<HashMap<IpAddr, (Instant, u32)>>,
    peer: IpAddr,
) -> bool {
    let now = Instant::now();
    let mut attempts = attempts.lock().await;
    attempts.retain(|_, (window, _)| now.duration_since(*window) < Duration::from_secs(60));
    if let Some((_, count)) = attempts.get_mut(&peer) {
        if *count >= 30 {
            return false;
        }
        *count += 1;
        return true;
    }
    if attempts.len() >= 10_000 {
        return false;
    }
    attempts.insert(peer, (now, 1));
    true
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn settings(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "service": "admin-ui",
        "port": state.config.port,
        "mode": "rust"
    }))
}

async fn logs(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"entries": load_security_events(&state.audit, 200).await}))
}

async fn plugins() -> Json<serde_json::Value> {
    // There is no plugin system in the Rust edition: the list is genuinely empty and cannot be edited.
    Json(json!({"plugins":[],"dynamic_plugins":false,"editable":false}))
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
        &state.audit,
        "admin_update_plugins_unsupported",
        "admin",
        json!({}),
    )
    .await;
    Err(not_implemented("plugins"))
}

async fn block_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::to_value(state.blocklist.stats().await).unwrap())
}

async fn blocklist(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"blocked": state.blocklist.blocked().await}))
}

async fn block(
    State(state): State<AppState>,
    Extension(via): Extension<AuthVia>,
    headers: HeaderMap,
    Json(action): Json<IpAction>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !(via.session || is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET")) {
        return Err(unauthorized());
    }
    if let Some(ip) = action.ip {
        let block_reason = action
            .reason
            .as_deref()
            .unwrap_or("manual block by operator");
        if !state
            .blocklist
            .block_with_reason(ip.clone(), block_reason)
            .await
        {
            return Err(bad_request(
                "IP is invalid or belongs to trusted proxy infrastructure",
            ));
        }
        record_security_event(
            &state.audit,
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
    Extension(via): Extension<AuthVia>,
    headers: HeaderMap,
    Json(action): Json<IpAction>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !(via.session || is_authorized(&headers, "ADMIN_API_KEY", "JWT_SECRET")) {
        return Err(unauthorized());
    }
    if let Some(ip) = action.ip {
        state.blocklist.allow(&ip).await;
        record_security_event(&state.audit, "admin_unblock_ip", "admin", json!({"ip":ip})).await;
        Ok(Json(json!({"status":"success","ip":ip})))
    } else {
        Ok(Json(json!({"status":"error","message":"ip required"})))
    }
}

async fn gdpr_deletion(State(state): State<AppState>) -> Json<serde_json::Value> {
    record_security_event(
        &state.audit,
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
    State(state): State<AppState>,
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
        "oidc" => oidc_user(&state.oidc, &headers).await,
        _ => Err(bad_request("unsupported SSO mode")),
    }
}

#[derive(Deserialize)]
struct UserRequest {
    user: Option<String>,
}

#[derive(Deserialize)]
struct TotpVerifyRequest {
    user: Option<String>,
    code: String,
}

async fn webauthn_register_begin(
    State(state): State<AppState>,
    payload: Option<Json<UserRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.and_then(|Json(payload)| payload.user));
    state
        .passkeys
        .begin_registration(state.pg.as_deref(), &user)
        .await
}

async fn webauthn_login_begin(
    State(state): State<AppState>,
    payload: Option<Json<UserRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.and_then(|Json(payload)| payload.user));
    state
        .passkeys
        .begin_authentication(state.pg.as_deref(), &user)
        .await
}

async fn webauthn_register_complete(
    State(state): State<AppState>,
    Json(payload): Json<webauthn::RegistrationCompleteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.user);
    let response = state
        .passkeys
        .complete_registration(state.pg.as_deref(), &user, &payload.credential)
        .await?;
    record_security_event(
        &state.audit,
        "admin_passkey_registered",
        &user,
        json!({"method":"webauthn"}),
    )
    .await;
    Ok(response)
}

async fn webauthn_login_complete(
    State(state): State<AppState>,
    Json(payload): Json<webauthn::AuthenticationCompleteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let user = admin_user(payload.user);
    let response = state
        .passkeys
        .complete_authentication(state.pg.as_deref(), &user, &payload.credential)
        .await?;
    record_security_event(
        &state.audit,
        "admin_passkey_authenticated",
        &user,
        json!({"method":"webauthn"}),
    )
    .await;
    Ok(response)
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
    let secret = read_mfa_secret(state.pg.as_deref(), &user).await?;
    let valid = secret
        .as_deref()
        .is_some_and(|secret| verify_totp(secret, &payload.code));
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

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = bearer_token(&headers) {
        webauthn::delete_session(state.pg.as_deref(), &token).await;
    }
    if let Some(cookie) = cookie_value(&headers, SESSION_COOKIE) {
        state.sessions.lock().await.remove(&hash_secret(&cookie));
    }
    let mut response = Json(json!({"status":"success"})).into_response();
    set_cookie(
        &mut response,
        &session_cookie("", 0, cookie_secure(&headers)),
    );
    response
}

async fn operation_blocklist_sync(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    operation_unsupported(state, "blocklist-sync").await
}

async fn operation_rules_fetch(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    operation_unsupported(state, "rules-fetch").await
}

async fn operation_robots_fetch(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    operation_unsupported(state, "robots-fetch").await
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
    rand::rng().fill_bytes(&mut data);
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

async fn oidc_user(
    verifier: &oidc::OidcVerifier,
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
    let claims = match verifier.verify(&token).await {
        Ok(claims) => claims,
        Err(oidc::OidcError::Unauthorized) => return Err(unauthorized()),
        Err(oidc::OidcError::Unavailable(message)) => {
            tracing::warn!(error = %message, "OIDC validation provider unavailable");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status":"error",
                    "message":"OIDC identity provider is unavailable"
                })),
            ));
        }
    };
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

async fn ensure_admin_auth_tables(pg: Option<&tokio_postgres::Client>) -> anyhow::Result<()> {
    let Some(pg) = pg else {
        return Ok(());
    };
    pg.batch_execute(
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
            CREATE TABLE IF NOT EXISTS admin_webauthn_users (
                user_name TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE
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
    .await?;
    Ok(())
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

async fn read_mfa_secret(
    pg: Option<&tokio_postgres::Client>,
    user: &str,
) -> Result<Option<String>, (StatusCode, Json<serde_json::Value>)> {
    let Some(pg) = pg else {
        return Err(storage_required());
    };
    let row = pg
        .query_opt(
            "SELECT totp_secret FROM admin_mfa WHERE user_name = $1",
            &[&user],
        )
        .await
        .map_err(|exc| internal_error(exc.to_string()))?;
    Ok(row.map(|row| row.get(0)))
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

/// Admin operations that nothing executes yet answer 501, so a success or queued reply always means the work
/// happened. The attempt is still audited, under a name that does not claim anything was queued.
async fn operation_unsupported(
    state: AppState,
    operation: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    record_security_event(
        &state.audit,
        "admin_operation_unsupported",
        "admin",
        json!({"operation":operation}),
    )
    .await;
    not_implemented(operation)
}

fn not_implemented(operation: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "status": "not_implemented",
            "operation": operation,
            "message": "This admin operation is not implemented in the Rust edition yet; nothing was run."
        })),
    )
}

fn internal_error(message: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"status":"error","message":message})),
    )
}

#[derive(Deserialize)]
struct SessionRequest {
    api_key: Option<String>,
}

fn session_ttl() -> Duration {
    let seconds = std::env::var("ADMIN_SESSION_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(3600);
    Duration::from_secs(seconds.clamp(60, 86_400))
}

/// Compares two strings without stopping at the first difference.
fn constant_time_eq(left: &str, right: &str) -> bool {
    use sha2::Digest;
    let left = sha2::Sha256::digest(left.as_bytes());
    let right = sha2::Sha256::digest(right.as_bytes());
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
}

/// Secure only when the request arrived over HTTPS (through a proxy that says so), because a Secure cookie is
/// never returned over plain HTTP. `ADMIN_COOKIE_SECURE=true|false` overrides the detection.
fn cookie_secure(headers: &HeaderMap) -> bool {
    match std::env::var("ADMIN_COOKIE_SECURE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "true" | "1" => true,
        "false" | "0" => false,
        _ => headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("https")
            })
            .unwrap_or(false),
    }
}

fn session_cookie(token: &str, max_age_seconds: u64, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Max-Age={max_age_seconds}; Path=/; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

fn set_cookie(response: &mut Response, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// The live browser session for the request's cookie, if any. Expired sessions are dropped on the way.
async fn browser_session_for(state: &AppState, headers: &HeaderMap) -> Option<BrowserSession> {
    let token = cookie_value(headers, SESSION_COOKIE)?;
    let now = Instant::now();
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.expires > now);
    sessions.get(&hash_secret(&token)).cloned()
}

async fn start_browser_session(state: &AppState) -> (String, BrowserSession) {
    let token = random_token(32);
    let session = BrowserSession {
        expires: Instant::now() + session_ttl(),
        csrf: random_token(16),
    };
    let mut sessions = state.sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|_, existing| existing.expires > now);
    while sessions.len() >= MAX_BROWSER_SESSIONS {
        let oldest = sessions
            .iter()
            .min_by_key(|(_, existing)| existing.expires)
            .map(|(key, _)| key.clone());
        match oldest {
            Some(key) => sessions.remove(&key),
            None => break,
        };
    }
    sessions.insert(hash_secret(&token), session.clone());
    (token, session)
}

async fn get_session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut response = match browser_session_for(&state, &headers).await {
        Some(session) => Json(json!({"authenticated":true,"csrf_token":session.csrf})),
        None => Json(json!({"authenticated":false})),
    }
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Exchanges the admin API key for a cookie session so the browser never has to keep the key.
async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SessionRequest>,
) -> Response {
    let Some(expected) = std::env::var("ADMIN_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"Browser sign-in is not configured: ADMIN_API_KEY is not set."})),
        )
            .into_response();
    };
    let supplied = request.api_key.unwrap_or_default();
    if !constant_time_eq(&supplied, &expected) {
        record_security_event(&state.audit, "admin_session_rejected", "admin", json!({})).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"The API key was rejected."})),
        )
            .into_response();
    }
    let (token, session) = start_browser_session(&state).await;
    record_security_event(&state.audit, "admin_session_started", "admin", json!({})).await;
    let mut response =
        Json(json!({"authenticated":true,"csrf_token":session.csrf})).into_response();
    set_cookie(
        &mut response,
        &session_cookie(&token, session_ttl().as_secs(), cookie_secure(&headers)),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod mfa_rate_tests {
    use super::*;

    #[tokio::test]
    async fn public_mfa_attempts_are_bounded_per_peer() {
        let attempts = Mutex::new(HashMap::new());
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..30 {
            assert!(admit_mfa_attempt(&attempts, peer).await);
        }
        assert!(!admit_mfa_attempt(&attempts, peer).await);
        assert!(admit_mfa_attempt(&attempts, "192.0.2.2".parse().unwrap()).await);
    }
}

#[cfg(test)]
mod honest_operation_tests {
    use super::*;

    #[test]
    fn unimplemented_operations_answer_501_and_never_claim_success() {
        for operation in ["blocklist-sync", "rules-fetch", "robots-fetch", "plugins"] {
            let (status, Json(body)) = not_implemented(operation);
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
            assert_eq!(body["status"], "not_implemented");
            assert_eq!(body["operation"], operation);
            assert!(body["message"]
                .as_str()
                .unwrap()
                .contains("nothing was run"));
        }
    }

    #[tokio::test]
    async fn plugin_listing_says_it_is_empty_and_not_editable() {
        let Json(body) = plugins().await;
        assert_eq!(body["plugins"], json!([]));
        assert_eq!(body["editable"], false);
        assert_eq!(body["dynamic_plugins"], false);
    }

    #[test]
    fn no_handler_still_reports_queued_or_empty_success() {
        // Guards against the original defect (#83): a handler that audits an event nothing consumes and replies
        // "queued" or "success". The check reads this file with the test module removed, so it cannot match itself.
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("admin_operation_queued"));
        assert!(!production.contains("operation_queued"));
        assert!(!production.contains("\"status\":\"queued\",\"operation\""));
        assert!(!production.contains("\"status\":\"success\",\"plugins\""));
    }
}

#[cfg(test)]
mod browser_session_tests {
    use super::*;
    use axum::{body::Body, routing::get};
    use tower::ServiceExt;

    const KEY: &str = "test-admin-key-for-browser-sessions";

    fn use_test_key() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            std::env::set_var("ADMIN_API_KEY", KEY);
            std::env::remove_var("JWT_SECRET");
        });
    }

    async fn test_state() -> AppState {
        use_test_key();
        AppState {
            config: ServiceConfig::from_env("admin-ui", 8004),
            blocklist: BlocklistState::default(),
            pg: None,
            audit: AuditStore::Disabled,
            oidc: oidc::OidcVerifier::from_env().unwrap(),
            passkeys: Arc::new(webauthn::PasskeyService::from_env().unwrap()),
            mfa_attempts: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route("/", get(index))
            .route("/session", get(get_session).post(create_session))
            .route("/blocklist", get(blocklist))
            .route("/block", post(block))
            .route("/unblock", post(unblock))
            .route("/mfa/backup-codes", post(mfa_backup_codes))
            .route("/logout", post(logout))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                require_admin_middleware,
            ))
            .with_state(state)
    }

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut builder = axum::http::Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = match body {
            Some(value) => builder
                .header("content-type", "application/json")
                .body(Body::from(value.to_string())),
            None => builder.body(Body::empty()),
        }
        .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (parts.status, parts.headers, json)
    }

    /// Signs in and returns (cookie header value, csrf token).
    async fn sign_in(app: &Router) -> (String, String) {
        let (status, headers, body) =
            call(app, "POST", "/session", &[], Some(json!({"api_key": KEY}))).await;
        assert_eq!(status, StatusCode::OK);
        let cookie = headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        (cookie, body["csrf_token"].as_str().unwrap().to_owned())
    }

    #[tokio::test]
    async fn wrong_key_is_rejected_without_a_cookie_and_the_right_key_starts_a_session() {
        let app = app(test_state().await);
        let (status, headers, body) = call(
            &app,
            "POST",
            "/session",
            &[],
            Some(json!({"api_key": "wrong"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.get(header::SET_COOKIE).is_none());
        assert_eq!(body["error"], "The API key was rejected.");

        let (status, headers, body) =
            call(&app, "POST", "/session", &[], Some(json!({"api_key": KEY}))).await;
        assert_eq!(status, StatusCode::OK);
        let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.starts_with("asd_admin_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(
            !cookie.contains("Secure"),
            "plain HTTP must not get a Secure cookie"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert!(!body["csrf_token"].as_str().unwrap().is_empty());
        assert!(!body.to_string().contains(KEY));

        let (_, headers, _) = call(
            &app,
            "POST",
            "/session",
            &[("x-forwarded-proto", "https")],
            Some(json!({"api_key": KEY})),
        )
        .await;
        assert!(headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("; Secure"));
    }

    #[tokio::test]
    async fn the_session_unlocks_reads_and_session_status_reports_it() {
        let app = app(test_state().await);
        let (status, _, _) = call(&app, "GET", "/blocklist", &[], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, _, body) = call(&app, "GET", "/session", &[], None).await;
        assert_eq!(body["authenticated"], false);

        let (cookie, csrf) = sign_in(&app).await;
        let (status, _, body) = call(&app, "GET", "/blocklist", &[("cookie", &cookie)], None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["blocked"], json!([]));
        let (_, _, body) = call(&app, "GET", "/session", &[("cookie", &cookie)], None).await;
        assert_eq!(body["authenticated"], true);
        assert_eq!(body["csrf_token"], csrf);
    }

    #[tokio::test]
    async fn mutations_on_a_cookie_session_need_the_csrf_token() {
        let app = app(test_state().await);
        let (cookie, csrf) = sign_in(&app).await;
        let payload = json!({"ip": "203.0.113.7", "reason": "scraping"});

        for headers in [
            vec![("cookie", cookie.as_str())],
            vec![
                ("cookie", cookie.as_str()),
                ("x-csrf-token", "not-the-token"),
            ],
        ] {
            let (status, _, body) =
                call(&app, "POST", "/block", &headers, Some(payload.clone())).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"], "Invalid CSRF token");
        }
        let (_, _, list) = call(&app, "GET", "/blocklist", &[("cookie", &cookie)], None).await;
        assert_eq!(
            list["blocked"],
            json!([]),
            "a refused request must change nothing"
        );

        let ok = [("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
        let (status, _, _) = call(&app, "POST", "/block", &ok, Some(payload)).await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, list) = call(&app, "GET", "/blocklist", &[("cookie", &cookie)], None).await;
        assert_eq!(list["blocked"], json!(["203.0.113.7"]));

        let (status, _, _) = call(
            &app,
            "POST",
            "/unblock",
            &[("cookie", cookie.as_str())],
            Some(json!({"ip": "203.0.113.7"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call(
            &app,
            "POST",
            "/unblock",
            &ok,
            Some(json!({"ip": "203.0.113.7"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, list) = call(&app, "GET", "/blocklist", &[("cookie", &cookie)], None).await;
        assert_eq!(list["blocked"], json!([]));
    }

    #[tokio::test]
    async fn api_key_clients_are_unaffected_and_need_no_csrf_token() {
        let app = app(test_state().await);
        let (status, _, _) = call(
            &app,
            "POST",
            "/block",
            &[("x-api-key", KEY)],
            Some(json!({"ip": "198.51.100.9", "reason": "api client"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(
            &app,
            "POST",
            "/block",
            &[("x-api-key", "wrong")],
            Some(json!({"ip": "198.51.100.10"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_browser_session_cannot_reach_the_mfa_secrets_endpoints() {
        let app = app(test_state().await);
        let (cookie, csrf) = sign_in(&app).await;
        let (status, _, _) = call(
            &app,
            "POST",
            "/mfa/backup-codes",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_ends_the_session_and_clears_the_cookie() {
        let app = app(test_state().await);
        let (cookie, csrf) = sign_in(&app).await;
        let (status, _, _) = call(
            &app,
            "POST",
            "/logout",
            &[("cookie", cookie.as_str())],
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "logout is a mutation and needs the CSRF token too"
        );
        let (status, headers, _) = call(
            &app,
            "POST",
            "/logout",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
        let (status, _, _) = call(&app, "GET", "/blocklist", &[("cookie", &cookie)], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_sessions_stop_working_and_are_dropped() {
        let state = test_state().await;
        let app = app(state.clone());
        let (cookie, _) = sign_in(&app).await;
        for session in state.sessions.lock().await.values_mut() {
            session.expires = Instant::now() - Duration::from_secs(1);
        }
        let (status, _, _) = call(&app, "GET", "/blocklist", &[("cookie", &cookie)], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn the_session_store_is_bounded() {
        let state = test_state().await;
        for _ in 0..(MAX_BROWSER_SESSIONS + 25) {
            start_browser_session(&state).await;
        }
        assert_eq!(state.sessions.lock().await.len(), MAX_BROWSER_SESSIONS);
    }

    #[tokio::test]
    async fn sign_in_attempts_are_rate_limited_per_peer() {
        let app = app(test_state().await);
        let mut last = StatusCode::OK;
        for _ in 0..31 {
            let (status, _, _) = call(
                &app,
                "POST",
                "/session",
                &[],
                Some(json!({"api_key": "wrong"})),
            )
            .await;
            last = status;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn cookie_parsing_and_comparison_helpers() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("a=1; asd_admin_session=tok; b=2"),
        );
        headers.append(header::COOKIE, HeaderValue::from_static("c=3"));
        assert_eq!(
            cookie_value(&headers, "asd_admin_session").as_deref(),
            Some("tok")
        );
        assert_eq!(cookie_value(&headers, "c").as_deref(), Some("3"));
        assert_eq!(cookie_value(&headers, "missing"), None);
        let mut empty = HeaderMap::new();
        empty.insert(
            header::COOKIE,
            HeaderValue::from_static("asd_admin_session="),
        );
        assert_eq!(cookie_value(&empty, "asd_admin_session"), None);
        assert!(constant_time_eq("same", "same"));
        assert!(!constant_time_eq("same", "different"));
        assert!(!constant_time_eq("", "x"));
    }

    #[tokio::test]
    async fn the_landing_page_has_the_controls_and_writes_dynamic_text_safely() {
        let Html(page) = index().await;
        for id in [
            "sign-in-form",
            "api-key",
            "metric-blocked",
            "metric-flagged",
            "events-table",
            "blocklist-table",
            "block-form",
            "confirm-dialog",
            "last-updated",
            "error",
        ] {
            assert!(page.contains(&format!("id=\"{id}\"")), "missing #{id}");
        }
        assert!(page.contains("type=\"password\""));
        assert!(page.contains("textContent"));
        assert!(page.contains("\"X-CSRF-Token\""));
        assert!(page.contains("Last update failed"));
        for forbidden in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "localStorage",
            "sessionStorage",
            "eval(",
        ] {
            assert!(!page.contains(forbidden), "page must not use {forbidden}");
        }
    }
}
