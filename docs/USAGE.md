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
- `AUDIT_STORAGE_BACKEND`: `auto` (default), `postgres`, `jsonl`, or `disabled`. `auto` uses PostgreSQL when connected and initializes a JSONL store at `AUDIT_JSONL_PATH` otherwise. Explicit PostgreSQL selection fails startup if the database is unavailable; invalid backend names also fail startup. The container image runs from the non-root user's writable home, so its default relative path resolves to `/home/appuser/data/security-events.jsonl`.
- `OTEL_EXPORTER_OTLP_ENDPOINT`: optional HTTP(S) OTLP/gRPC collector endpoint. When set, all shared-server HTTP spans are batch-exported with W3C `traceparent` extraction and flushed during process shutdown; malformed endpoints fail startup.
- `ADMIN_API_KEY`, `ESCALATION_API_KEY`, `PUBLIC_BLOCKLIST_API_KEY`, `JWT_SECRET`: API-key and JWT protection for mutation routes.
- `WEBHOOK_SHARED_SECRET`: HMAC secret for AI service webhooks.
- `CAPTCHA_TOKEN_SECRET`, `CAPTCHA_TOKEN_TTL_SECONDS`: shared HMAC key and lifetime for one-time CAPTCHA verification tokens. Configure the same secret on every CAPTCHA replica.

- `CLOUD_MODEL_API_URL`, `CLOUD_MODEL_API_KEY`, `MODEL_PROVIDER`, `MODEL_NAME`: upstream model proxy configuration.
- `DETECTION_MODEL_PATH`: optional path to a versioned logistic-regression
  artifact emitted by `POST /training/train` on `rag-trainer`. The escalation
  engine validates and loads it once at startup and again on `POST
  /admin/reload_model`. An unset path, or a configured path whose file does
  not exist yet (e.g. a freshly created shared volume before the first
  persisted training run), retains the documented heuristic fallback; a
  configured path whose file exists but is malformed or otherwise unreadable
  fails startup, and `/admin/reload_model` always errors on a missing or
  invalid artifact rather than silently keeping the previous detector.
- `MODEL_URI=mcp://primary/classify` plus `MCP_SERVER_PRIMARY_URL`, `MCP_SERVER_PRIMARY_AUTH_TOKEN`, and `MCP_SERVER_PRIMARY_TIMEOUT`: optional MCP model proxying compatible with `request-guard-mcp`. Leave `MODEL_URI` unset to keep MCP disabled.
  The public cloud-proxy strips caller-asserted TLS provenance. When the
  immediate peer is a configured trusted Envoy/Cloudflare collector and the
  current attestation key is configured, it overwrites and signs the
  infrastructure-derived values before MCP forwarding. See
  [Trusted TLS fingerprint attestation](TLS_FINGERPRINT_ATTESTATION.md).
- `PAYMENT_GATEWAY_URL`, `PAYMENT_PROVIDER`, `PAYMENT_API_KEY`: optional payment gateway forwarding for pay-per-crawl flows.
- `ADMIN_UI_SSO_ENABLED`, `ADMIN_UI_SSO_MODE`, `ADMIN_UI_OIDC_*`, `ADMIN_UI_SAML_*`: admin SSO configuration. OIDC uses provider discovery (or an explicit JWKS URL), asymmetric signatures, `kid` selection, issuer/audience/expiry validation, and a bounded rotating-key cache. HTTP provider URLs are rejected except for loopback development endpoints.
- `ADMIN_UI_WEBAUTHN_ORIGIN`, `ADMIN_UI_WEBAUTHN_RP_ID`, `ADMIN_UI_WEBAUTHN_RP_NAME`: the browser origin and stable relying-party identity for native passkey registration and authentication. Changing the RP ID after credentials are registered invalidates those credentials. PostgreSQL is required for one-time ceremony state, credentials, and hashed admin sessions.
- `EDGE_ALLOWED_DOMAINS`, `REAL_BACKEND_HOST`, `RULES_URL`, `CDN_PURGE_URL`: edge operations configuration.
- `ENABLE_GLOBAL_CDN`, `CLOUD_CDN_PROVIDER`, and `SECURITY_CDN_TRUSTED_PROXY_CIDRS`: optional Cloudflare ingress integration. Configure Cloudflare's published proxy ranges so originating client IPs—not Cloudflare edge addresses—are evaluated and blocked.

The CAPTCHA service admits up to 60 challenges per connecting IP each minute and
retains at most 10,000 active challenges and 10,000 issued tokens per replica.
Capacity or rate exhaustion returns HTTP 429. The public admin MFA verification
routes admit up to 30 attempts per connecting IP each minute. If these services
are behind a proxy, the limit applies to the proxy's connection address; set
matching limits at the ingress for individual clients.

Escalation scoring checks both the supplied request path and a normalized path
with up to three percent-decoding passes, backslash and repeated-slash
normalization, dot-segment removal, and ASCII case folding. Paths longer than
8192 bytes retain only the raw-path check. The `verified_bot` field in request
JSON is ignored; only service-derived verification can grant benign crawler
credit. Public blocklist reports require `PUBLIC_BLOCKLIST_API_KEY`, a valid
client IP outside local and configured trusted ranges, and a reason of at most
256 bytes.

Cloudflare is treated as an ingress/CDN boundary, not as a general outbound proxy. Ordinary model, payment, rules, and backend requests continue directly to their configured destinations, avoiding unnecessary Cloudflare traffic charges. When Cloudflare integration is enabled and the request/bot thresholds are exceeded, `config-recommender` returns an advisory to consider Under Attack Mode; it never changes the Cloudflare account automatically.

### Distributed attack incident alerts

Set the same `INCIDENT_EVALUATOR_API_KEY` on `escalation-engine` and `config-recommender`. Compose supplies `INCIDENT_EVALUATOR_URL`; set it to the authenticated `/incident/evaluate` endpoint when running outside Compose. Set `ADMIN_ALERT_WEBHOOK_URL` to deliver an operator alert, and optionally set `ADMIN_ALERT_WEBHOOK_BEARER_TOKEN` for its receiver. An empty evaluator URL, API key, or webhook URL disables the live alert path.

The escalation engine aggregates suspicious decisions for `INCIDENT_MAX_WINDOW_SECONDS` (default 300) and caps memory with `INCIDENT_MAX_SAMPLES` (default 10,000). The evaluator requires `CLOUDFLARE_ATTACK_RECOMMENDATION_MIN_REQUESTS` (default 100), `CLOUDFLARE_ATTACK_RECOMMENDATION_MIN_BOT_RATIO` (default 0.25), and `INCIDENT_MIN_UNIQUE_SOURCES` (default 20). It suppresses repeat alerts for `INCIDENT_ALERT_COOLDOWN_SECONDS` (default 900). Set `INCIDENT_PRIMARY_HEALTH_URL` and `INCIDENT_BACKUP_HEALTH_URL` to include a manual failover recommendation only if the primary is unhealthy and the backup is healthy. A Cloudflare recommendation is also manual; the services do not call the Cloudflare API or change routing. Window aggregation and cooldown are process-local, so use one replica of each service until shared incident state is added. Use synthetic traffic and a local webhook receiver for drills.

Each service also accepts a `*_PORT` variable matching its package name in uppercase, for example `ESCALATION_ENGINE_PORT` or `RAG_TRAINER_PORT`. Security-event writers report persistence and malformed-record errors through structured logs instead of silently discarding them.

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
| `rag-trainer` | 8014 | Reviewed-label model training, ingest, and fine-tuning JSONL export |

After the stack is up, run:

```powershell
.\scripts\parity_smoke.ps1
```

Passkey clients use the native ceremony routes:

- `POST /webauthn/register/begin` with an optional `{ "user": "name" }`, authenticated by the admin API key or an existing admin session.
- `POST /webauthn/register/complete` with `{ "user": "name", "credential": <RegisterPublicKeyCredential> }` and the same admin authorization.
- `POST /webauthn/login/begin` with the user name, followed by `POST /webauthn/login/complete` with `{ "user": "name", "credential": <PublicKeyCredential> }`.

Successful authentication returns a bearer session token. Only its SHA-256 hash is persisted, it expires according to `ADMIN_UI_SESSION_TTL_SECONDS`, and `/logout` revokes it. The legacy `/passkey/register` and `/passkey/login` routes are aliases for the corresponding begin operations.

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
  -Headers @{"x-api-key"=$env:PAY_PER_CRAWL_API_KEY} `
  -ContentType application/json `
  -Body '{"name":"ExampleCrawler","token":"crawler-token","purpose":"licensed indexing"}'

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8012/pay `
  -Headers @{"x-api-key"=$env:PAY_PER_CRAWL_API_KEY} `
  -ContentType application/json `
  -Body '{"token":"crawler-token","amount":10.0}'

Invoke-WebRequest `
  -Uri http://127.0.0.1:8012/proxy/licensed-page `
  -Headers @{"x-crawler-token"="crawler-token"}
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

## Release Artifacts

Release automation runs on tags matching `v*.*.*`:

- `.github/workflows/release-images.yml` publishes `ghcr.io/rhamenator/ai-scraping-defense-rust`.
- `.github/workflows/release-binaries.yml` builds native Linux x64, Windows x64, macOS Intel, and macOS Apple Silicon bundles containing all service binaries and matching SHA-256 checksums.

Stable semver tags such as `v1.2.3` publish `1.2.3`, `1.2`, and `latest` image tags. Prerelease tags such as `v1.2.3-rc.1` publish only the prerelease version tag and GitHub prerelease assets.

## Verification

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## License

AI Scraping Defense Rust is licensed under the GNU General Public License v3.0 or later. See [../LICENSE](../LICENSE).
