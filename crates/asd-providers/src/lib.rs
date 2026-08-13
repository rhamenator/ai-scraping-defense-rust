use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};

#[derive(Clone, Debug)]
pub struct ModelProvider {
    endpoint: String,
    api_key: Option<String>,
    kind: ProviderKind,
}

#[derive(Clone, Debug)]
pub enum ProviderKind {
    GenericHttp,
    OpenAiCompatible,
    AnthropicCompatible,
    CohereCompatible,
    GeminiCompatible,
    MistralCompatible,
    OllamaCompatible,
    LocalHttp,
    Mcp {
        server_label: String,
        tool_name: String,
        timeout_secs: u64,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ModelRequest {
    pub prompt: Option<String>,
    pub messages: Option<serde_json::Value>,
    pub max_tokens: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ModelProvider {
    pub fn new(endpoint: String, api_key: Option<String>, kind: ProviderKind) -> Self {
        Self {
            endpoint,
            api_key,
            kind,
        }
    }

    pub fn from_env() -> Option<Self> {
        if let Some(provider) = Self::mcp_from_env() {
            return Some(provider);
        }

        let endpoint = env_non_empty("CLOUD_MODEL_API_URL")?;
        let api_key = std::env::var("CLOUD_MODEL_API_KEY")
            .ok()
            .filter(|value| !value.is_empty());
        let kind = match std::env::var("MODEL_PROVIDER")
            .unwrap_or_else(|_| "generic-http".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "openai" | "openai-compatible" => ProviderKind::OpenAiCompatible,
            "anthropic" | "anthropic-compatible" => ProviderKind::AnthropicCompatible,
            "cohere" | "cohere-compatible" => ProviderKind::CohereCompatible,
            "gemini" | "google" | "gemini-compatible" => ProviderKind::GeminiCompatible,
            "mistral" | "mistral-compatible" => ProviderKind::MistralCompatible,
            "ollama" | "ollama-compatible" => ProviderKind::OllamaCompatible,
            "local" | "local-http" => ProviderKind::LocalHttp,
            _ => ProviderKind::GenericHttp,
        };
        Some(Self::new(endpoint, api_key, kind))
    }

    pub async fn predict(&self, request: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        if matches!(self.kind, ProviderKind::Mcp { .. }) {
            return self.predict_mcp(request).await;
        }

        let payload = self.normalize_payload(request);
        let timeout_seconds = std::env::var("MODEL_PROVIDER_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30)
            .max(1);
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(timeout_seconds))
            .build()?;
        let mut outbound = client.post(&self.endpoint).json(&payload);
        if let Some(api_key) = &self.api_key {
            outbound = match self.kind {
                ProviderKind::AnthropicCompatible => outbound
                    .header("x-api-key", api_key)
                    .header("anthropic-version", anthropic_version()),
                ProviderKind::GeminiCompatible => outbound.header("x-goog-api-key", api_key),
                ProviderKind::LocalHttp | ProviderKind::OllamaCompatible => outbound,
                _ => outbound.bearer_auth(api_key),
            };
        }
        let mut response = outbound.send().await?;
        let status = response.status();
        let maximum_bytes = std::env::var("MODEL_PROVIDER_MAX_RESPONSE_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4 * 1024 * 1024);
        if response
            .content_length()
            .is_some_and(|length| length as usize > maximum_bytes)
        {
            anyhow::bail!("model provider response exceeds configured limit");
        }
        let mut response_bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if response_bytes.len().saturating_add(chunk.len()) > maximum_bytes {
                anyhow::bail!("model provider response exceeds configured limit");
            }
            response_bytes.extend_from_slice(&chunk);
        }
        let body =
            serde_json::from_slice::<serde_json::Value>(&response_bytes).unwrap_or_else(|_| {
                json!({
                    "text": String::from_utf8_lossy(&response_bytes),
                    "parse_error": "upstream response was not JSON"
                })
            });
        Ok(json!({
            "status": if status.is_success() { "success" } else { "error" },
            "provider": self.kind.name(),
            "upstream_status": status.as_u16(),
            "response": body
        }))
    }

    fn normalize_payload(&self, request: serde_json::Value) -> serde_json::Value {
        match self.kind {
            ProviderKind::GenericHttp | ProviderKind::LocalHttp => request,
            ProviderKind::Mcp { .. } => request,
            ProviderKind::OpenAiCompatible | ProviderKind::MistralCompatible => {
                let prompt = request
                    .get("prompt")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                json!({
                    "model": model_name(&request),
                    "messages": request.get("messages").cloned().unwrap_or_else(|| {
                        json!([{"role":"user","content":prompt}])
                    }),
                    "max_tokens": request.get("max_tokens").cloned().unwrap_or_else(|| json!(256))
                })
            }
            ProviderKind::AnthropicCompatible => {
                let prompt = request
                    .get("prompt")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                json!({
                    "model": model_name(&request),
                    "messages": request.get("messages").cloned().unwrap_or_else(|| {
                        json!([{"role":"user","content":prompt}])
                    }),
                    "max_tokens": request.get("max_tokens").cloned().unwrap_or_else(|| json!(256))
                })
            }
            ProviderKind::CohereCompatible => {
                let prompt = request
                    .get("prompt")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                json!({
                    "model": model_name(&request),
                    "message": request
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| json!(prompt)),
                    "max_tokens": request.get("max_tokens").cloned().unwrap_or_else(|| json!(256))
                })
            }
            ProviderKind::GeminiCompatible => {
                let prompt = request
                    .get("prompt")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                json!({
                    "contents": request.get("contents").cloned().unwrap_or_else(|| {
                        json!([{"parts":[{"text":prompt}]}])
                    })
                })
            }
            ProviderKind::OllamaCompatible => {
                let prompt = request
                    .get("prompt")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                json!({
                    "model": model_name(&request),
                    "prompt": prompt,
                    "stream": request
                        .get("stream")
                        .cloned()
                        .unwrap_or(serde_json::Value::Bool(false))
                })
            }
        }
    }

    fn mcp_from_env() -> Option<Self> {
        let explicit_mcp_provider = std::env::var("MODEL_PROVIDER")
            .map(|value| value.eq_ignore_ascii_case("mcp"))
            .unwrap_or(false);
        let model_uri = env_non_empty("MODEL_URI")
            .or_else(|| explicit_mcp_provider.then(|| "mcp://primary/classify".to_string()))?;

        let (server_label, tool_name) = parse_mcp_model_uri(&model_uri)?;
        let env_prefix = format!("MCP_SERVER_{}", server_label.to_ascii_uppercase());
        let transport =
            env_non_empty(&format!("{env_prefix}_TRANSPORT")).unwrap_or_else(|| "ws".to_string());
        if !transport.eq_ignore_ascii_case("ws") && !transport.eq_ignore_ascii_case("websocket") {
            return None;
        }

        let endpoint = env_non_empty(&format!("{env_prefix}_URL"))
            .or_else(|| env_non_empty("CLOUD_MODEL_API_URL"))?;
        let api_key = env_non_empty(&format!("{env_prefix}_AUTH_TOKEN"))
            .or_else(|| env_non_empty("CLOUD_MODEL_API_KEY"));
        let timeout_secs = env_non_empty(&format!("{env_prefix}_TIMEOUT"))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10);

        Some(Self::new(
            endpoint,
            api_key,
            ProviderKind::Mcp {
                server_label,
                tool_name,
                timeout_secs,
            },
        ))
    }

    async fn predict_mcp(&self, request: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let ProviderKind::Mcp {
            server_label,
            tool_name,
            timeout_secs,
        } = &self.kind
        else {
            unreachable!("predict_mcp is only called for MCP providers");
        };

        let request = sanitize_mcp_payload(request);
        let operation_timeout = Duration::from_secs((*timeout_secs).max(1));
        let mut ws_request = self.endpoint.as_str().into_client_request()?;
        if let Some(api_key) = &self.api_key {
            ws_request
                .headers_mut()
                .insert("Authorization", format!("Bearer {api_key}").parse()?);
        }

        let (mut socket, _) = timeout(operation_timeout, connect_async(ws_request)).await??;
        let rpc_id = json_rpc_id();
        let rpc_request = json!({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": tool_name,
            "params": request
        });

        timeout(
            operation_timeout,
            futures_util::SinkExt::send(&mut socket, Message::Text(rpc_request.to_string().into())),
        )
        .await??;

        let message = timeout(
            operation_timeout,
            futures_util::StreamExt::next(&mut socket),
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("MCP server closed before sending a response"))??;

        let response_text = match message {
            Message::Text(text) => text.to_string(),
            Message::Binary(bytes) => String::from_utf8(bytes.to_vec())?,
            other => anyhow::bail!("unexpected MCP websocket response: {other:?}"),
        };
        let response: serde_json::Value = serde_json::from_str(&response_text)?;
        if let Some(error) = response.get("error") {
            anyhow::bail!("MCP tool error: {error}");
        }

        Ok(json!({
            "status": "success",
            "provider": self.kind.name(),
            "server": server_label,
            "tool": tool_name,
            "upstream_status": 200,
            "response": response.get("result").cloned().unwrap_or(response)
        }))
    }
}

impl ProviderKind {
    fn name(&self) -> &'static str {
        match self {
            ProviderKind::GenericHttp => "generic-http",
            ProviderKind::OpenAiCompatible => "openai-compatible",
            ProviderKind::AnthropicCompatible => "anthropic-compatible",
            ProviderKind::CohereCompatible => "cohere-compatible",
            ProviderKind::GeminiCompatible => "gemini-compatible",
            ProviderKind::MistralCompatible => "mistral-compatible",
            ProviderKind::OllamaCompatible => "ollama-compatible",
            ProviderKind::LocalHttp => "local-http",
            ProviderKind::Mcp { .. } => "mcp",
        }
    }
}

fn parse_mcp_model_uri(model_uri: &str) -> Option<(String, String)> {
    let remainder = model_uri.strip_prefix("mcp://")?;
    let (server_label, tool_name) = remainder.split_once('/')?;
    if server_label.is_empty() || tool_name.is_empty() {
        return None;
    }

    Some((server_label.to_string(), tool_name.to_string()))
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn json_rpc_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("rust-{nanos}")
}

fn model_name(request: &serde_json::Value) -> serde_json::Value {
    request
        .get("model")
        .cloned()
        .or_else(|| {
            std::env::var("MODEL_NAME")
                .ok()
                .map(serde_json::Value::String)
        })
        .unwrap_or_else(|| json!("default"))
}

fn anthropic_version() -> String {
    std::env::var("ANTHROPIC_VERSION").unwrap_or_else(|_| "2023-06-01".to_string())
}

fn sanitize_mcp_payload(mut request: serde_json::Value) -> serde_json::Value {
    if let Some(object) = request.as_object_mut() {
        object.remove("tls_fingerprint_verified");
        let fingerprint = asd_core::TlsFingerprint {
            ja3: asd_core::normalize_ja3(object.get("tls_ja3").and_then(serde_json::Value::as_str)),
            ja4: asd_core::normalize_ja4(object.get("tls_ja4").and_then(serde_json::Value::as_str)),
            source: asd_core::normalize_tls_source(
                object
                    .get("tls_fingerprint_source")
                    .and_then(serde_json::Value::as_str),
            )
            .unwrap_or_default(),
        };
        let token = object
            .get("tls_fingerprint_attestation")
            .and_then(serde_json::Value::as_str);
        let key = std::env::var("TLS_FINGERPRINT_ATTESTATION_KEY").unwrap_or_default();
        let previous_key =
            std::env::var("TLS_FINGERPRINT_ATTESTATION_PREVIOUS_KEY").unwrap_or_default();
        let max_age = std::env::var("TLS_FINGERPRINT_ATTESTATION_MAX_AGE_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(60);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or_default();
        let verified = asd_core::verify_tls_fingerprint_attestation_with_keys(
            token,
            &[&key, &previous_key],
            max_age,
            &asd_core::TlsAttestationContext {
                now,
                client_ip: object
                    .get("ip")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
                method: object
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("GET"),
                path: object
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
                fingerprint: &fingerprint,
            },
        );
        if verified {
            if let Some(ja3) = fingerprint.ja3 {
                object.insert("tls_ja3".into(), serde_json::Value::String(ja3));
            }
            if let Some(ja4) = fingerprint.ja4 {
                object.insert("tls_ja4".into(), serde_json::Value::String(ja4));
            }
            object.insert(
                "tls_fingerprint_source".into(),
                serde_json::Value::String(fingerprint.source),
            );
        } else {
            object.remove("tls_ja3");
            object.remove("tls_ja4");
            object.remove("tls_fingerprint_source");
            object.remove("tls_fingerprint_attestation");
        }
    }
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mcp_model_uri() {
        assert_eq!(
            parse_mcp_model_uri("mcp://primary/classify"),
            Some(("primary".to_string(), "classify".to_string()))
        );
    }

    #[test]
    fn rejects_non_mcp_model_uri() {
        assert_eq!(
            parse_mcp_model_uri("https://example.invalid/classify"),
            None
        );
        assert_eq!(parse_mcp_model_uri("mcp://primary"), None);
        assert_eq!(parse_mcp_model_uri("mcp:///classify"), None);
    }

    #[test]
    fn mcp_payload_drops_untrusted_tls_fingerprint_claims() {
        let payload = json!({
            "ip": "198.51.100.5",
            "tls_ja3": "72a589da586844d7f0818ce684948eea",
            "tls_ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
            "tls_fingerprint_source": "client-claim"
        });

        let sanitized = sanitize_mcp_payload(payload);
        assert_eq!(sanitized["ip"], "198.51.100.5");
        assert!(sanitized.get("tls_ja3").is_none());
        assert!(sanitized.get("tls_ja4").is_none());
        assert!(sanitized.get("tls_fingerprint_source").is_none());
    }

    #[test]
    fn mcp_payload_retains_a_valid_bound_attestation() {
        let key = "0123456789abcdef0123456789abcdef";
        std::env::set_var("TLS_FINGERPRINT_ATTESTATION_KEY", key);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let fingerprint = asd_core::TlsFingerprint {
            ja3: Some("72a589da586844d7f0818ce684948eea".into()),
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            source: "envoy".into(),
        };
        let token = asd_core::create_tls_fingerprint_attestation(
            key,
            now,
            "198.51.100.5",
            "GET",
            "/products",
            &fingerprint,
        )
        .unwrap();
        let payload = json!({
            "ip": "198.51.100.5",
            "method": "GET",
            "path": "/products",
            "tls_ja3": fingerprint.ja3,
            "tls_ja4": fingerprint.ja4,
            "tls_fingerprint_source": fingerprint.source,
            "tls_fingerprint_attestation": token
        });
        let sanitized = sanitize_mcp_payload(payload);
        assert_eq!(
            sanitized["tls_fingerprint_source"],
            serde_json::Value::String("envoy".into())
        );
        assert!(sanitized.get("tls_fingerprint_attestation").is_some());
        std::env::remove_var("TLS_FINGERPRINT_ATTESTATION_KEY");
    }
}
