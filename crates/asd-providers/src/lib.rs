use serde::{Deserialize, Serialize};
use serde_json::json;

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
        let endpoint = std::env::var("CLOUD_MODEL_API_URL")
            .ok()
            .filter(|value| !value.is_empty())?;
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
        let payload = self.normalize_payload(request);
        let client = reqwest::Client::new();
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
        let response = outbound.send().await?;
        let status = response.status();
        let body = response
            .json::<serde_json::Value>()
            .await
            .unwrap_or_else(|_| json!({}));
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
        }
    }
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
