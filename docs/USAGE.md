# Usage Guide

This guide covers local development, service configuration, deployment, and common API workflows for AI Scraping Defense Rust.

## Requirements

- Rust 1.88, pinned by `rust-toolchain.toml`
- Docker and Docker Compose for the local multi-service stack
- Redis for shared blocklist and request-frequency state
- PostgreSQL for audit events, tarpit corpus reads, crawler credits, admin auth state, and training records

## Configuration

Start from the sample environment file:

```powershell
cp config/sample.env .env
```

Important settings:

- `REDIS_HOST`, `REDIS_PORT`: Redis connection used by blocklist and frequency tracking.
- `POSTGRES_ENABLED`, `PG_HOST`, `PG_PORT`, `PG_DBNAME`, `PG_USER`, `PG_PASSWORD`: PostgreSQL connection used by persisted service state.
- `ADMIN_API_KEY`, `ESCALATION_API_KEY`, `PUBLIC_BLOCKLIST_API_KEY`, `JWT_SECRET`: API-key and JWT protection for mutation routes.
- `WEBHOOK_SHARED_SECRET`: HMAC secret for AI service webhooks.
- `CLOUD_MODEL_API_URL`, `CLOUD_MODEL_API_KEY`, `MODEL_PROVIDER`, `MODEL_NAME`: upstream model proxy configuration.
- `MODEL_URI=mcp://primary/classify` plus `MCP_SERVER_PRIMARY_URL`, `MCP_SERVER_PRIMARY_AUTH_TOKEN`, and `MCP_SERVER_PRIMARY_TIMEOUT`: optional MCP model proxying compatible with `request-guard-mcp`. Leave `MODEL_URI` unset to keep MCP disabled.
- `PAYMENT_GATEWAY_URL`, `PAYMENT_PROVIDER`, `PAYMENT_API_KEY`: optional payment gateway forwarding for pay-per-crawl flows.
- `ADMIN_UI_SSO_ENABLED`, `ADMIN_UI_SSO_MODE`, `ADMIN_UI_OIDC_*`, `ADMIN_UI_SAML_*`: admin SSO configuration.
- `EDGE_ALLOWED_DOMAINS`, `REAL_BACKEND_HOST`, `RULES_URL`, `CDN_PURGE_URL`: edge operations configuration.

Each service also accepts a `*_PORT` variable matching its package name in uppercase, for example `ESCALATION_ENGINE_PORT` or `RAG_TRAINER_PORT`.

## Run One Service

```powershell
cargo run -p escalation-engine
```

Useful local service commands:

```powershell
cargo run -p admin-ui
cargo run -p ai-service
cargo run -p tarpit-api
cargo run -p edge-ops
cargo run -p rag-trainer
```

## Run the Full Stack

```powershell
docker compose up --build
```

Default ports:

| Service | Port | Purpose |
| --- | ---: | --- |
| `ai-service` | 8001 | Webhook-driven block/allow/flag actions |
| `escalation-engine` | 8002 | Request scoring and escalation decisions |
| `tarpit-api` | 8003 | Bot tarpit pages and fake assets |
| `admin-ui` | 8004 | Admin dashboard and mutation endpoints |
| `captcha-service` | 8005 | Challenge, solve, and verify flows |
| `cloud-dashboard` | 8006 | Installation registration and metrics fanout |
| `config-recommender` | 8007 | Configuration recommendations |
| `cloud-proxy` | 8008 | Model provider proxy |
| `prompt-router` | 8009 | Local/cloud prompt routing |
| `public-blocklist` | 8011 | Public blocklist list/report endpoints |
| `pay-per-crawl` | 8012 | Crawler registration, credit, and proxy charging |
| `edge-ops` | 8013 | Robots/rules/WAF/CDN/TLS/DDoS/blocklist operations |
| `rag-trainer` | 8014 | Training ingest and fine-tuning JSONL export |

After the stack is up, run:

```powershell
.\scripts\parity_smoke.ps1
```

## API Examples

Score a request:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8002/escalate `
  -ContentType application/json `
  -Body '{"ip":"203.0.113.10","path":"/wp-admin","user_agent":"python-requests/2"}'
```

Block an IP through the admin API:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8004/block `
  -Headers @{"x-api-key"=$env:ADMIN_API_KEY} `
  -ContentType application/json `
  -Body '{"ip":"203.0.113.10","reason":"scraper"}'
```

Generate a tarpit response:

```powershell
Invoke-RestMethod http://127.0.0.1:8003/tarpit/example/path
```

Register a pay-per-crawl client:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8012/register-crawler `
  -ContentType application/json `
  -Body '{"name":"ExampleCrawler","token":"crawler-token","purpose":"licensed indexing","credit":10.0}'
```

Export fine-tuning JSONL:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8014/finetune/export `
  -ContentType application/json `
  -Body '{"records":[{"ip":"203.0.113.10","path":"/wp-admin","user_agent":"python-requests/2","status":403}]}'
```

More endpoint examples are in [API_EXAMPLES.md](API_EXAMPLES.md).

## Authentication

Mutation routes use one or both of:

- `x-api-key` headers matched against service-specific environment variables.
- `Authorization: Bearer <jwt>` checked with `JWT_SECRET` for HS256 JWTs.

Admin SSO supports:

- OIDC-style HS256 JWT validation with issuer, audience, role, and group checks.
- SAML/trusted-header mode for deployments where a reverse proxy or identity provider validates assertions upstream.

## Deployment

Build the image:

```powershell
docker build -t ai-scraping-defense-rust:local .
```

Use the starter Kubernetes manifest:

```powershell
kubectl apply -f kubernetes/rust-stack.yaml
```

Use the Helm starter chart:

```powershell
helm install asd-rust helm/ai-scraping-defense-rust
```

The Kubernetes and Helm files are starter artifacts. Tune image names, secrets, ingress, resource requests, and persistence for your cluster.

## Verification

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## License

AI Scraping Defense Rust is licensed under the GNU General Public License v3.0 or later. See [../LICENSE](../LICENSE).
