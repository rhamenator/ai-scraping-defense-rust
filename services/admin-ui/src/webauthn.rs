use axum::{http::StatusCode, Json};
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::Client;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Webauthn, WebauthnBuilder,
};

pub type ApiError = (StatusCode, Json<Value>);
pub type ApiResult = Result<Json<Value>, ApiError>;

const REGISTRATION_PURPOSE: &str = "webauthn-registration";
const AUTHENTICATION_PURPOSE: &str = "webauthn-authentication";

#[derive(Debug, Deserialize)]
pub struct RegistrationCompleteRequest {
    pub user: Option<String>,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationCompleteRequest {
    pub user: Option<String>,
    pub credential: PublicKeyCredential,
}

#[derive(Clone)]
pub struct PasskeyService {
    webauthn: Webauthn,
    challenge_ttl_seconds: i32,
    session_ttl_seconds: i32,
}

impl PasskeyService {
    pub fn from_env() -> anyhow::Result<Self> {
        let origin = std::env::var("ADMIN_UI_WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8004".to_string());
        let origin = Url::parse(&origin)
            .map_err(|error| anyhow::anyhow!("ADMIN_UI_WEBAUTHN_ORIGIN is invalid: {error}"))?;
        let rp_id = std::env::var("ADMIN_UI_WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| origin.domain().unwrap_or("localhost").to_string());
        let rp_name = std::env::var("ADMIN_UI_WEBAUTHN_RP_NAME")
            .unwrap_or_else(|_| "AI Scraping Defense Admin".to_string());
        let mut builder = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(|error| {
                anyhow::anyhow!("invalid WebAuthn relying-party configuration: {error}")
            })?
            .rp_name(&rp_name);
        if env_bool("ADMIN_UI_WEBAUTHN_ALLOW_SUBDOMAINS", false) {
            builder = builder.allow_subdomains(true);
        }
        if env_bool("ADMIN_UI_WEBAUTHN_ALLOW_ANY_PORT", false) {
            builder = builder.allow_any_port(true);
        }
        for extra_origin in env_list("ADMIN_UI_WEBAUTHN_ADDITIONAL_ORIGINS") {
            let parsed = Url::parse(&extra_origin).map_err(|error| {
                anyhow::anyhow!("invalid WebAuthn additional origin {extra_origin:?}: {error}")
            })?;
            builder = builder.append_allowed_origin(&parsed);
        }
        let webauthn = builder
            .build()
            .map_err(|error| anyhow::anyhow!("could not initialize WebAuthn: {error}"))?;
        Ok(Self {
            webauthn,
            challenge_ttl_seconds: env_i32("ADMIN_UI_WEBAUTHN_CHALLENGE_TTL_SECONDS", 300, 60, 900),
            session_ttl_seconds: env_i32("ADMIN_UI_SESSION_TTL_SECONDS", 3600, 300, 86_400),
        })
    }

    pub async fn begin_registration(&self, pg: Option<&Client>, user: &str) -> ApiResult {
        let pg = require_storage(pg)?;
        let user_id = ensure_user_id(pg, user).await?;
        let passkeys = load_passkeys(pg, user).await?;
        let exclusions = (!passkeys.is_empty()).then(|| {
            passkeys
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect()
        });
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_id, user, user, exclusions)
            .map_err(|_| invalid("could not begin WebAuthn registration"))?;
        store_challenge(
            pg,
            user,
            REGISTRATION_PURPOSE,
            &state,
            self.challenge_ttl_seconds,
        )
        .await?;
        Ok(Json(
            json!({"status":"success", "user":user, "options":options}),
        ))
    }

    pub async fn complete_registration(
        &self,
        pg: Option<&Client>,
        user: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> ApiResult {
        let pg = require_storage(pg)?;
        let state: PasskeyRegistration = consume_challenge(pg, user, REGISTRATION_PURPOSE).await?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(|_| invalid("WebAuthn registration response was not valid"))?;
        let credential_id = credential_key(passkey.cred_id())?;
        let public_key = serde_json::to_value(&passkey)
            .map_err(|_| internal("could not persist WebAuthn credential"))?;
        let inserted = pg
            .execute(
                "INSERT INTO admin_credentials (user_name, credential_id, public_key)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (credential_id) DO NOTHING",
                &[&user, &credential_id, &public_key],
            )
            .await
            .map_err(|_| internal("could not persist WebAuthn credential"))?;
        if inserted != 1 {
            return Err(conflict("credential is already registered"));
        }
        Ok(Json(
            json!({"status":"success", "user":user, "registered":true}),
        ))
    }

    pub async fn begin_authentication(&self, pg: Option<&Client>, user: &str) -> ApiResult {
        let pg = require_storage(pg)?;
        let passkeys = load_passkeys(pg, user).await?;
        if passkeys.is_empty() {
            return Err(not_found("no passkeys are registered for this user"));
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| invalid("could not begin WebAuthn authentication"))?;
        store_challenge(
            pg,
            user,
            AUTHENTICATION_PURPOSE,
            &state,
            self.challenge_ttl_seconds,
        )
        .await?;
        Ok(Json(
            json!({"status":"success", "user":user, "options":options}),
        ))
    }

    pub async fn complete_authentication(
        &self,
        pg: Option<&Client>,
        user: &str,
        credential: &PublicKeyCredential,
    ) -> ApiResult {
        let pg = require_storage(pg)?;
        let state: PasskeyAuthentication =
            consume_challenge(pg, user, AUTHENTICATION_PURPOSE).await?;
        let mut passkeys = load_passkeys(pg, user).await?;
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, &state)
            .map_err(|_| invalid("WebAuthn authentication response was not valid"))?;
        let mut matched = None;
        for passkey in &mut passkeys {
            if passkey.update_credential(&result).is_some() {
                matched = Some(passkey);
                break;
            }
        }
        let matched =
            matched.ok_or_else(|| invalid("authentication used an unknown credential"))?;
        let credential_id = credential_key(matched.cred_id())?;
        let public_key = serde_json::to_value(matched)
            .map_err(|_| internal("could not update WebAuthn credential"))?;
        let updated = pg
            .execute(
                "UPDATE admin_credentials SET public_key = $3
                 WHERE user_name = $1 AND credential_id = $2",
                &[&user, &credential_id, &public_key],
            )
            .await
            .map_err(|_| internal("could not update WebAuthn credential"))?;
        if updated != 1 {
            return Err(internal(
                "WebAuthn credential disappeared during authentication",
            ));
        }
        let token = random_token(32);
        let token_hash = hash_token(&token);
        pg.execute(
            "INSERT INTO admin_sessions (token, user_name, expires_at)
             VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 second'))",
            &[&token_hash, &user, &self.session_ttl_seconds],
        )
        .await
        .map_err(|_| internal("could not create admin session"))?;
        Ok(Json(json!({
            "status":"success",
            "user":user,
            "token":token,
            "token_type":"Bearer",
            "expires_in":self.session_ttl_seconds
        })))
    }
}

pub async fn session_is_valid(pg: Option<&Client>, token: &str) -> bool {
    let Some(pg) = pg else {
        return false;
    };
    let token_hash = hash_token(token);
    match pg
        .query_opt(
            "SELECT 1 FROM admin_sessions WHERE token = $1 AND expires_at > NOW()",
            &[&token_hash],
        )
        .await
    {
        Ok(row) => row.is_some(),
        Err(error) => {
            tracing::warn!(%error, "could not validate persisted admin session");
            false
        }
    }
}

pub async fn delete_session(pg: Option<&Client>, token: &str) {
    if let Some(pg) = pg {
        let token_hash = hash_token(token);
        if let Err(error) = pg
            .execute(
                "DELETE FROM admin_sessions WHERE token = $1",
                &[&token_hash],
            )
            .await
        {
            tracing::warn!(%error, "could not revoke persisted admin session");
        }
    }
}

async fn ensure_user_id(pg: &Client, user: &str) -> Result<Uuid, ApiError> {
    let candidate = Uuid::new_v4().to_string();
    pg.execute(
        "INSERT INTO admin_webauthn_users (user_name, user_id)
         VALUES ($1, $2) ON CONFLICT (user_name) DO NOTHING",
        &[&user, &candidate],
    )
    .await
    .map_err(|_| internal("could not persist WebAuthn user"))?;
    let row = pg
        .query_one(
            "SELECT user_id FROM admin_webauthn_users WHERE user_name = $1",
            &[&user],
        )
        .await
        .map_err(|_| internal("could not load WebAuthn user"))?;
    let value: String = row.get(0);
    Uuid::parse_str(&value).map_err(|_| internal("stored WebAuthn user ID is invalid"))
}

async fn load_passkeys(pg: &Client, user: &str) -> Result<Vec<Passkey>, ApiError> {
    let rows = pg
        .query(
            "SELECT public_key FROM admin_credentials WHERE user_name = $1 ORDER BY created_at",
            &[&user],
        )
        .await
        .map_err(|_| internal("could not load WebAuthn credentials"))?;
    rows.into_iter()
        .map(|row| {
            let value: Value = row.get(0);
            serde_json::from_value(value)
                .map_err(|_| internal("stored WebAuthn credential is invalid"))
        })
        .collect()
}

async fn store_challenge<T: serde::Serialize>(
    pg: &Client,
    user: &str,
    purpose: &str,
    state: &T,
    ttl_seconds: i32,
) -> Result<(), ApiError> {
    let state = serde_json::to_string(state)
        .map_err(|_| internal("could not serialize WebAuthn ceremony state"))?;
    pg.execute(
        "INSERT INTO admin_challenges (user_name, purpose, challenge, expires_at)
         VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 second'))
         ON CONFLICT (user_name, purpose) DO UPDATE
         SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at",
        &[&user, &purpose, &state, &ttl_seconds],
    )
    .await
    .map_err(|_| internal("could not persist WebAuthn ceremony state"))?;
    Ok(())
}

async fn consume_challenge<T: serde::de::DeserializeOwned>(
    pg: &Client,
    user: &str,
    purpose: &str,
) -> Result<T, ApiError> {
    let row = pg
        .query_opt(
            "DELETE FROM admin_challenges
             WHERE user_name = $1 AND purpose = $2 AND expires_at > NOW()
             RETURNING challenge",
            &[&user, &purpose],
        )
        .await
        .map_err(|_| internal("could not consume WebAuthn ceremony state"))?
        .ok_or_else(|| invalid("WebAuthn ceremony is missing, expired, or already used"))?;
    let value: String = row.get(0);
    serde_json::from_str(&value).map_err(|_| internal("stored WebAuthn ceremony state is invalid"))
}

fn credential_key<T: serde::Serialize>(credential_id: &T) -> Result<String, ApiError> {
    serde_json::to_string(credential_id)
        .map_err(|_| internal("could not encode WebAuthn credential ID"))
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    hex::encode(value)
}

fn hash_token(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

fn require_storage(pg: Option<&Client>) -> Result<&Client, ApiError> {
    pg.ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"error", "message":"Postgres is required for persisted admin auth state"})),
        )
    })
}

fn invalid(message: &'static str) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status":"error", "message":message})),
    )
}

fn not_found(message: &'static str) -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"status":"error", "message":message})),
    )
}

fn conflict(message: &'static str) -> ApiError {
    (
        StatusCode::CONFLICT,
        Json(json!({"status":"error", "message":message})),
    )
}

fn internal(message: &'static str) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"status":"error", "message":message})),
    )
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn env_i32(name: &str, default: i32, min: i32, max: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};

    #[test]
    fn defaults_form_a_valid_local_relying_party() {
        let service = PasskeyService::from_env().expect("default WebAuthn config should be valid");
        assert_eq!(service.challenge_ttl_seconds, 300);
        assert_eq!(service.session_ttl_seconds, 3600);
        assert_eq!(
            service.webauthn.get_allowed_origins()[0].host_str(),
            Some("localhost")
        );
    }

    #[test]
    fn token_hash_does_not_store_bearer_secret() {
        let token = "secret-session-token";
        assert_ne!(hash_token(token), token);
        assert_eq!(hash_token(token), hash_token(token));
    }

    #[test]
    fn native_registration_and_authentication_verify_real_signatures() {
        let origin = Url::parse("https://localhost:8443").expect("test origin");
        let webauthn = WebauthnBuilder::new("localhost", &origin)
            .expect("test relying party")
            .build()
            .expect("test WebAuthn service");
        let (creation, registration_state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "admin", "Admin", None)
            .expect("registration challenge");
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = authenticator
            .do_registration(origin.clone(), creation)
            .expect("software authenticator registration");
        let passkey = webauthn
            .finish_passkey_registration(&registration, &registration_state)
            .expect("server-side attestation and registration verification");

        let (request, authentication_state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .expect("authentication challenge");
        let assertion = authenticator
            .do_authentication(origin, request)
            .expect("software authenticator assertion");
        let result = webauthn
            .finish_passkey_authentication(&assertion, &authentication_state)
            .expect("server-side assertion signature verification");

        assert_eq!(result.cred_id(), passkey.cred_id());
        assert!(result.counter() > 0);
        let mut updated = passkey;
        assert_eq!(updated.update_credential(&result), Some(true));
    }
}
