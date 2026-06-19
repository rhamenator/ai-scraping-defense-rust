# AI Scraping Defense Rust

This is a Rust-first sibling implementation of the Python-based
`ai-scraping-defense` stack. It mirrors the main service boundaries and public
endpoint shapes while keeping integrations small and explicit.

## Scope

Implemented baseline services:

- `escalation-engine`: `/escalate`, `/metrics`, `/admin/reload_plugins`
- `ai-service`: `/health`, `/webhook`
- `tarpit-api`: `/health`, `/`, `/tarpit/*path`
- `admin-ui`: dashboard, settings, logs, plugins, blocklist endpoints
- `captcha-service`: `/challenge`, `/solve`, `/verify`
- `cloud-dashboard`: installation registration and metrics fanout endpoints
- `cloud-proxy`: `/health`, `/api/chat`
- `config-recommender`: `/recommendations`
- `edge-ops`: robots/rules fetching, WAF/CDN/TLS/DDoS operations, blocklist sync
- `pay-per-crawl`: crawler registration, payment, proxy charging
- `prompt-router`: `/health`, `/route`
- `public-blocklist`: `/list`, `/list/auth`, `/report`
- `rag-trainer`: request labeling, training ingest, fine-tuning JSONL export

The first goal is operational parity at the API and deployment boundary.
Provider integrations use typed HTTP adapters that can be pointed at the
configured upstreams.

## Layout

- `crates/asd-core`: shared config, health responses, HMAC, blocklist state
- `crates/asd-detection`: feature extraction, fingerprinting, scoring
- `crates/asd-tarpit`: deterministic tarpit page and fake asset generation
- `services/*`: one binary per runtime service
- `config/`: sample runtime configuration
- `docker-compose.yaml`: local stack similar to the Python composition

## Run Locally

```bash
cargo run -p escalation-engine
cargo run -p ai-service
cargo run -p tarpit-api
```

Each service accepts a `*_PORT` environment variable matching its package name in
uppercase, for example `ESCALATION_ENGINE_PORT=8010`.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

If Windows reports a missing Rust toolchain manifest, repair or reinstall the
pinned toolchain first:

```powershell
rustup toolchain uninstall 1.88.0-x86_64-pc-windows-msvc
rustup toolchain install 1.88.0-x86_64-pc-windows-msvc
```
