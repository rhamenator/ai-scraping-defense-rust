use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

const MAX_PROVIDER_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum OidcError {
    Unauthorized,
    Unavailable(String),
}

#[derive(Clone)]
pub struct OidcVerifier(Option<Arc<VerifierInner>>);

struct VerifierInner {
    client: Client,
    config: OidcConfig,
    cache: RwLock<JwksCache>,
    refresh_lock: Mutex<()>,
}

#[derive(Clone)]
struct OidcConfig {
    issuer: String,
    audience: String,
    discovery_url: Url,
    explicit_jwks_url: Option<Url>,
    allowed_algorithms: Vec<Algorithm>,
    cache_ttl: Duration,
    leeway_seconds: u64,
    allow_http: bool,
}

#[derive(Default)]
struct JwksCache {
    keys: Option<JwkSet>,
    fetched_at: Option<Instant>,
    last_forced_refresh: Option<Instant>,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

impl OidcVerifier {
    pub fn from_env() -> anyhow::Result<Self> {
        let enabled = env_bool("ADMIN_UI_SSO_ENABLED", false)
            && env_string("ADMIN_UI_SSO_MODE", "oidc").eq_ignore_ascii_case("oidc");
        if !enabled {
            return Ok(Self(None));
        }
        let issuer = required_env("ADMIN_UI_OIDC_ISSUER")?;
        let audience = required_env("ADMIN_UI_OIDC_AUDIENCE")?;
        let allow_http = env_bool("ADMIN_UI_OIDC_ALLOW_HTTP", false);
        let issuer_url = parse_provider_url("ADMIN_UI_OIDC_ISSUER", &issuer, allow_http)?;
        if issuer_url.query().is_some() || issuer_url.fragment().is_some() {
            anyhow::bail!("ADMIN_UI_OIDC_ISSUER cannot contain a query string or fragment");
        }
        let discovery_url = match std::env::var("ADMIN_UI_OIDC_DISCOVERY_URL") {
            Ok(value) if !value.trim().is_empty() => {
                parse_provider_url("ADMIN_UI_OIDC_DISCOVERY_URL", value.trim(), allow_http)?
            }
            _ => parse_provider_url(
                "ADMIN_UI_OIDC_ISSUER",
                &format!(
                    "{}/.well-known/openid-configuration",
                    issuer.trim_end_matches('/')
                ),
                allow_http,
            )?,
        };
        let explicit_jwks_url = match std::env::var("ADMIN_UI_OIDC_JWKS_URL") {
            Ok(value) if !value.trim().is_empty() => Some(parse_provider_url(
                "ADMIN_UI_OIDC_JWKS_URL",
                value.trim(),
                allow_http,
            )?),
            _ => None,
        };
        let allowed_algorithms = parse_algorithms(&env_string(
            "ADMIN_UI_OIDC_ALLOWED_ALGORITHMS",
            "RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,EdDSA",
        ))?;
        let timeout_seconds = env_u64("ADMIN_UI_OIDC_HTTP_TIMEOUT_SECONDS", 10, 2, 60);
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()?;
        Ok(Self(Some(Arc::new(VerifierInner {
            client,
            config: OidcConfig {
                issuer,
                audience,
                discovery_url,
                explicit_jwks_url,
                allowed_algorithms,
                cache_ttl: Duration::from_secs(env_u64(
                    "ADMIN_UI_OIDC_JWKS_CACHE_SECONDS",
                    300,
                    30,
                    86_400,
                )),
                leeway_seconds: env_u64("ADMIN_UI_OIDC_CLOCK_SKEW_SECONDS", 60, 0, 300),
                allow_http,
            },
            cache: RwLock::new(JwksCache::default()),
            refresh_lock: Mutex::new(()),
        }))))
    }

    pub async fn verify(&self, token: &str) -> Result<Value, OidcError> {
        match &self.0 {
            None => Err(OidcError::Unavailable(
                "OIDC verifier is disabled".to_string(),
            )),
            Some(inner) => inner.verify(token).await,
        }
    }
}

impl VerifierInner {
    async fn verify(&self, token: &str) -> Result<Value, OidcError> {
        let header = decode_header(token).map_err(|_| OidcError::Unauthorized)?;
        if !self.config.allowed_algorithms.contains(&header.alg)
            || header.alg.family() == jsonwebtoken::AlgorithmFamily::Hmac
        {
            return Err(OidcError::Unauthorized);
        }
        let kid = header.kid.as_deref().ok_or(OidcError::Unauthorized)?;
        self.refresh_if_stale(false).await?;
        let mut key = self.find_key(kid).await;
        if key.is_none() {
            self.refresh_if_stale(true).await?;
            key = self.find_key(kid).await;
        }
        let key = key.ok_or(OidcError::Unauthorized)?;
        match self.decode_with_key(token, header.alg, &key) {
            Ok(claims) => Ok(claims),
            Err(error) if matches!(error.kind(), ErrorKind::InvalidSignature) => {
                self.refresh_if_stale(true).await?;
                let rotated_key = self.find_key(kid).await.ok_or(OidcError::Unauthorized)?;
                self.decode_with_key(token, header.alg, &rotated_key)
                    .map_err(|_| OidcError::Unauthorized)
            }
            Err(_) => Err(OidcError::Unauthorized),
        }
    }

    fn decode_with_key(
        &self,
        token: &str,
        algorithm: Algorithm,
        jwk: &Jwk,
    ) -> jsonwebtoken::errors::Result<Value> {
        validate_jwk(jwk, algorithm)?;
        let key = DecodingKey::from_jwk(jwk)?;
        let mut validation = Validation::new(algorithm);
        validation.leeway = self.config.leeway_seconds;
        validation.validate_nbf = true;
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        decode::<Value>(token, &key, &validation).map(|data| data.claims)
    }

    async fn find_key(&self, kid: &str) -> Option<Jwk> {
        self.cache
            .read()
            .await
            .keys
            .as_ref()
            .and_then(|keys| keys.find(kid))
            .cloned()
    }

    async fn refresh_if_stale(&self, force: bool) -> Result<(), OidcError> {
        if !force && !self.cache_is_stale().await {
            return Ok(());
        }
        let _guard = self.refresh_lock.lock().await;
        if force
            && self
                .cache
                .read()
                .await
                .last_forced_refresh
                .is_some_and(|time| time.elapsed() < Duration::from_secs(5))
        {
            return Ok(());
        }
        if !force && !self.cache_is_stale().await {
            return Ok(());
        }
        let keys = self.fetch_keys().await?;
        let mut cache = self.cache.write().await;
        cache.keys = Some(keys);
        cache.fetched_at = Some(Instant::now());
        if force {
            cache.last_forced_refresh = Some(Instant::now());
        }
        Ok(())
    }

    async fn cache_is_stale(&self) -> bool {
        let cache = self.cache.read().await;
        cache.keys.is_none()
            || cache
                .fetched_at
                .is_none_or(|time| time.elapsed() >= self.config.cache_ttl)
    }

    async fn fetch_keys(&self) -> Result<JwkSet, OidcError> {
        let jwks_url = match &self.config.explicit_jwks_url {
            Some(url) => url.clone(),
            None => {
                let discovery: DiscoveryDocument =
                    self.fetch_json(&self.config.discovery_url).await?;
                if discovery.issuer != self.config.issuer {
                    return Err(OidcError::Unavailable(
                        "OIDC discovery issuer did not match configured issuer".to_string(),
                    ));
                }
                parse_provider_url(
                    "discovered jwks_uri",
                    &discovery.jwks_uri,
                    self.config.allow_http,
                )
                .map_err(|error| OidcError::Unavailable(error.to_string()))?
            }
        };
        let keys: JwkSet = self.fetch_json(&jwks_url).await?;
        validate_jwks(&keys)?;
        Ok(keys)
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &Url) -> Result<T, OidcError> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|error| {
                OidcError::Unavailable(format!(
                    "OIDC provider request failed for {}: {error}",
                    safe_url(url)
                ))
            })?
            .error_for_status()
            .map_err(|error| {
                OidcError::Unavailable(format!(
                    "OIDC provider returned an error for {}: {error}",
                    safe_url(url)
                ))
            })?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_DOCUMENT_BYTES as u64)
        {
            return Err(OidcError::Unavailable(format!(
                "OIDC provider document exceeded size limit at {}",
                safe_url(url)
            )));
        }
        let bytes = response.bytes().await.map_err(|error| {
            OidcError::Unavailable(format!(
                "could not read OIDC provider response from {}: {error}",
                safe_url(url)
            ))
        })?;
        if bytes.len() > MAX_PROVIDER_DOCUMENT_BYTES {
            return Err(OidcError::Unavailable(format!(
                "OIDC provider document exceeded size limit at {}",
                safe_url(url)
            )));
        }
        serde_json::from_slice(&bytes).map_err(|error| {
            OidcError::Unavailable(format!(
                "OIDC provider returned invalid JSON from {}: {error}",
                safe_url(url)
            ))
        })
    }
}

fn validate_jwk(jwk: &Jwk, algorithm: Algorithm) -> jsonwebtoken::errors::Result<()> {
    use jsonwebtoken::errors::new_error;
    if matches!(
        jwk.algorithm,
        AlgorithmParameters::OctetKey(_) | AlgorithmParameters::Other(_)
    ) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    if jwk
        .common
        .key_algorithm
        .is_some_and(|key_algorithm| Algorithm::try_from(key_algorithm).ok() != Some(algorithm))
    {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|usage| usage != &PublicKeyUse::Signature)
    {
        return Err(new_error(ErrorKind::InvalidKeyFormat));
    }
    if jwk
        .common
        .key_operations
        .as_ref()
        .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        return Err(new_error(ErrorKind::InvalidKeyFormat));
    }
    Ok(())
}

fn validate_jwks(keys: &JwkSet) -> Result<(), OidcError> {
    if keys.keys.is_empty() {
        return Err(OidcError::Unavailable(
            "OIDC JWKS document did not contain keys".to_string(),
        ));
    }
    let mut kids = std::collections::HashSet::new();
    for key in &keys.keys {
        let kid = key
            .common
            .key_id
            .as_deref()
            .filter(|kid| !kid.is_empty())
            .ok_or_else(|| {
                OidcError::Unavailable("OIDC JWKS contained a key without a kid".to_string())
            })?;
        if !kids.insert(kid) {
            return Err(OidcError::Unavailable(
                "OIDC JWKS contained duplicate kid values".to_string(),
            ));
        }
    }
    Ok(())
}

fn parse_algorithms(value: &str) -> anyhow::Result<Vec<Algorithm>> {
    let algorithms = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(Algorithm::from_str)
        .collect::<Result<Vec<_>, _>>()?;
    if algorithms.is_empty()
        || algorithms
            .iter()
            .any(|algorithm| algorithm.family() == jsonwebtoken::AlgorithmFamily::Hmac)
    {
        anyhow::bail!("ADMIN_UI_OIDC_ALLOWED_ALGORITHMS must contain only asymmetric algorithms");
    }
    Ok(algorithms)
}

fn safe_url(url: &Url) -> String {
    let mut safe = url.clone();
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn parse_provider_url(name: &str, value: &str, allow_http: bool) -> anyhow::Result<Url> {
    let url = Url::parse(value).map_err(|error| anyhow::anyhow!("{name} is invalid: {error}"))?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && (allow_http || loopback)) {
        anyhow::bail!("{name} must use HTTPS (HTTP is accepted only for loopback or explicit test configuration)");
    }
    if url.username() != "" || url.password().is_some() || url.host_str().is_none() {
        anyhow::bail!("{name} must be an absolute provider URL without embedded credentials");
    }
    Ok(url)
}

fn required_env(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).unwrap_or_default();
    if value.trim().is_empty() {
        anyhow::bail!("{name} is required when OIDC SSO is enabled");
    }
    Ok(value.trim().to_string())
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
    use aws_lc_rs::signature::KeyPair as _;
    use axum::{extract::State, routing::get, Json, Router};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn symmetric_algorithms_are_never_accepted_for_jwks() {
        assert!(parse_algorithms("RS256,ES256").is_ok());
        assert!(parse_algorithms("RS256,HS256").is_err());
        assert!(parse_algorithms("").is_err());
    }

    #[test]
    fn provider_urls_require_https_except_for_loopback() {
        assert!(parse_provider_url("issuer", "https://id.example.test", false).is_ok());
        assert!(parse_provider_url("issuer", "http://localhost:9000", false).is_ok());
        assert!(parse_provider_url("issuer", "http://127.0.0.1:9000", false).is_ok());
        assert!(parse_provider_url("issuer", "http://id.example.test", false).is_err());
        assert!(parse_provider_url("issuer", "https://user@id.example.test", false).is_err());
    }

    #[tokio::test]
    async fn discovery_jwks_and_key_rotation_verify_asymmetric_tokens() {
        let key_one = test_key("key-one");
        let jwks = Arc::new(RwLock::new(jsonwebtoken::jwk::JwkSet {
            keys: vec![key_one.1.clone()],
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock identity provider");
        let address = listener.local_addr().expect("mock provider address");
        let issuer = format!("http://{address}");
        let discovery = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("http://{address}/jwks")
        });
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get({
                    let discovery = discovery.clone();
                    move || {
                        let discovery = discovery.clone();
                        async move { Json(discovery) }
                    }
                }),
            )
            .route(
                "/jwks",
                get(|State(keys): State<Arc<RwLock<JwkSet>>>| async move {
                    Json(keys.read().await.clone())
                }),
            )
            .with_state(jwks.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock provider server");
        });

        let verifier = OidcVerifier(Some(Arc::new(VerifierInner {
            client: Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .expect("test HTTP client"),
            config: OidcConfig {
                issuer: issuer.clone(),
                audience: "admin-ui".to_string(),
                discovery_url: Url::parse(&format!("{issuer}/.well-known/openid-configuration"))
                    .expect("test discovery URL"),
                explicit_jwks_url: None,
                allowed_algorithms: vec![Algorithm::RS256],
                cache_ttl: Duration::from_secs(3600),
                leeway_seconds: 0,
                allow_http: false,
            },
            cache: RwLock::new(JwksCache::default()),
            refresh_lock: Mutex::new(()),
        })));

        let token_one = test_token(&key_one.0, "key-one", &issuer, "admin-ui");
        let claims = verifier.verify(&token_one).await.expect("valid first key");
        assert_eq!(claims["sub"], "admin");

        let key_two = test_key("key-two");
        *jwks.write().await = JwkSet {
            keys: vec![key_two.1.clone()],
        };
        let rotated = test_token(&key_two.0, "key-two", &issuer, "admin-ui");
        assert!(verifier.verify(&rotated).await.is_ok());

        let wrong_audience = test_token(&key_two.0, "key-two", &issuer, "other-service");
        assert!(matches!(
            verifier.verify(&wrong_audience).await,
            Err(OidcError::Unauthorized)
        ));
        server.abort();
    }

    fn test_key(kid: &str) -> (EncodingKey, Jwk) {
        let private = KeyPair::generate(KeySize::Rsa2048).expect("generate test RSA key");
        let der = private.as_der().expect("encode test RSA key");
        let public = PublicKeyComponents::<Vec<u8>>::from(private.public_key());
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty":"RSA",
            "kid":kid,
            "alg":"RS256",
            "use":"sig",
            "key_ops":["verify"],
            "n":URL_SAFE_NO_PAD.encode(public.n),
            "e":URL_SAFE_NO_PAD.encode(public.e)
        }))
        .expect("build test JWK");
        (EncodingKey::from_rsa_der(der.as_ref()), jwk)
    }

    fn test_token(key: &EncodingKey, kid: &str, issuer: &str, audience: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &serde_json::json!({
                "sub":"admin",
                "iss":issuer,
                "aud":audience,
                "exp":jsonwebtoken::get_current_timestamp() + 300,
                "nbf":jsonwebtoken::get_current_timestamp().saturating_sub(1)
            }),
            key,
        )
        .expect("sign test token")
    }
}
