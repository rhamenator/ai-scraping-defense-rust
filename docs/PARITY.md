# Parity Map

This document maps the Rust workspace to the Python `ai-scraping-defense`
runtime services.

| Python service | Rust service | Parity status |
| --- | --- | --- |
| `src/escalation/escalation_engine.py` | `services/escalation-engine` | Endpoint parity for `/escalate`, `/metrics`, `/admin/reload_plugins`; Redis frequency tracking, Redis blocklist writes, API-key/JWT admin auth, and PostgreSQL security event recording are implemented. |
| `src/ai_service/main.py` | `services/ai-service` | Endpoint parity for `/health` and `/webhook`; HMAC verification, Redis block/allow/flag actions, and PostgreSQL audit events are implemented. |
| `src/tarpit/tarpit_api.py` | `services/tarpit-api` | Endpoint parity for `/health`, `/`, `/tarpit/*`; dynamic HTML generation is implemented in Rust and can pull Markov words from PostgreSQL when available. |
| `src/admin_ui/admin_ui.py` | `services/admin-ui` | Core admin routes plus persisted passkey/WebAuthn challenge, credential, MFA, backup-code, logout/session flows, metrics, operations triggers, Redis blocklist management, API-key/JWT mutation auth, and PostgreSQL event log reads are implemented. |
| `src/captcha/*` | `services/captcha-service` | Challenge, solve, and verify endpoints implemented with a local token baseline. |
| `src/cloud_dashboard/cloud_dashboard_api.py` | `services/cloud-dashboard` | Register, push metrics, fetch metrics, and websocket handshake implemented. |
| `cloud-proxy/main.py` | `services/cloud-proxy` | `/health` and `/api/chat` endpoint shape implemented; forwards through a provider-adapter crate to `CLOUD_MODEL_API_URL` when configured, and reports `not_configured` when no upstream is set. |
| `prompt-router/main.py` | `services/prompt-router` | `/health` and `/route` endpoint shape implemented with token-based routing and cloud-proxy forwarding. |
| `src/config_recommender/recommender_api.py` | `services/config-recommender` | `/recommendations` implemented with baseline recommendations. |
| `src/public_blocklist/public_blocklist_api.py` | `services/public-blocklist` | `/list`, `/list/auth`, and `/report` implemented with Redis-backed state and in-memory fallback. |
| `src/pay_per_crawl/proxy.py` | `services/pay-per-crawl` | Registration, payment, and proxy charging are implemented with PostgreSQL persistence and optional provider-shaped HTTP payment gateway forwarding via `PAYMENT_GATEWAY_URL`. |
| `src/admin_ui/sso.py` | `services/admin-ui` | OIDC-style HS256 bearer/header token validation and SAML-style trusted header validation are implemented with issuer, audience, role, and group checks. |
| `src/util/*` edge operations | `services/edge-ops` | Robots fetching, WAF rules fetching, WAF reload requests, CDN purge forwarding, TLS/DDoS status, community/peer blocklist sync, and security scoring endpoints are implemented. |
| `src/rag/training.py` | `services/rag-trainer` | Request labeling, training ingest, PostgreSQL persistence, and fine-tuning JSONL/provenance export are implemented with Rust heuristics. |

## Intentional Differences

- Blocklist and frequency persistence use Redis when configured, with in-memory
  fallback for development. Security events, tarpit corpus reads, and
  pay-per-crawl credits use PostgreSQL when configured.
- Python dynamic plugins are not loaded by the Rust engine. The Rust equivalent
  should use explicit trait-based extension crates or sidecars.
- Provider SDKs are represented by a typed HTTP adapter layer for generic HTTP,
  OpenAI-compatible, Anthropic-compatible, Cohere-compatible,
  Gemini-compatible, Mistral-compatible, Ollama-compatible, and local HTTP
  upstreams.
- WebAuthn/passkey/MFA routes now persist challenges, credentials, TOTP
  secrets, backup-code hashes, and sessions. Full FIDO2 attestation and
  signature verification can be layered onto the stored credential model.
- Payment forwarding supports generic HTTP, Stripe-shaped, PayPal-shaped,
  Braintree-shaped, Square-shaped, Adyen-shaped, Authorize.Net-shaped, and
  internal ledger payloads for customer, charge, refund, and balance flows.
- Deployment parity includes Docker Compose, Kubernetes starter manifests, a
  Helm starter chart, a live parity smoke script, and a GitHub Actions Rust CI
  workflow.
- The Rust stack favors typed request/response structs and explicit thresholds
  over broad dynamic dictionaries.

## Next Parity Work

1. Add full browser authenticator FIDO2 attestation/signature verification and
   encrypted credential storage.
2. Add native asymmetric OIDC verification through JWKS/RS256 and richer SAML
   assertion parsing when trusted reverse-proxy headers are not enough.
3. Expand `rag-trainer` from heuristic labeling/export into native model
   training artifact generation.
4. Add fixture-level live replay tests for representative Python request bodies,
   beyond the current service health smoke script.
