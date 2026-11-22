# Changelog

## [Unreleased]

### Security

- Update `url` to 2.5.9 (and `form_urlencoded` to 1.2.3) to fix RUSTSEC-2026-0592, a stack overflow in `Url::origin()` on deeply nested `blob:` URLs. Lockfile-only change.

### Changed

- The admin service no longer claims work it does not do (#83). `POST /operations/blocklist-sync`, `/operations/rules-fetch` and `/operations/robots-fetch` and `POST /plugins` now return `501 Not Implemented` with `{"status":"not_implemented",...}` instead of `queued` or `success`, because nothing in the Rust edition executes them. The attempt is still audited, as `admin_operation_unsupported` or `admin_update_plugins_unsupported` (previously `admin_operation_queued` and `admin_update_plugins`). `GET /plugins` now also reports `"editable": false`.

## [0.1.9] - 2026-11-22

### Security

- Bound AI service webhook and CAPTCHA solve/verify request bodies to 16 KiB before JSON or form decoding; oversized requests return 413.

## [0.1.8] - 2026-11-21

### Added

- Flagged tarpit clients now have a Redis per-IP hop limit (`TAR_PIT_MAX_HOPS=250`, `TAR_PIT_HOP_WINDOW_SECONDS=86400`). The next hit returns 403 and stores `Tarpit hop limit exceeded (N hits in Ws)` in the existing blocklist key with `BLOCKLIST_TTL_SECONDS`. Set the maximum to `0` to disable the limit. Redis failures fail open. Served tarpit hits are recorded as `tarpit_hit` audit events with path, client, and reason, flag the IP, and are forwarded to `ESCALATION_ENDPOINT` when configured (#75).

## [0.1.7] - 2026-11-20

### Changed

- Blocks now expire. Each block is stored as its own Redis key, `blocklist:<ip>`, with an expiry of `BLOCKLIST_TTL_SECONDS` (default 86400, 24 hours; the same setting and default as the Python edition, and the .NET edition's 1440 minutes). The key's value is the reason for the block. Blocking an address again restarts its expiry, `POST /unblock` still removes it immediately, and `BLOCKLIST_TTL_SECONDS=0` keeps blocks permanent. Previously blocks lived in a Redis set with no expiry, so a block made in error or against a spoofed address lasted until an operator found it. Entries left in the old set by earlier releases are moved to expiring keys when a service starts, which means they now expire after the configured lifetime too. The admin and escalation engines record the reason for each block.

## [0.1.6] - 2026-11-20

### Security

- `config-recommender` `GET /recommendations` and `edge-ops` `GET /security/score` now require an operator key (`INCIDENT_EVALUATOR_API_KEY` or `EDGE_OPS_API_KEY`, or a valid JWT). They previously answered anonymously, disclosing the tarpit and block thresholds and acting as a scoring oracle (#69).

### Fixed

- Docker Compose: services now wait for a healthy Redis (escalation-engine, ai-service, admin-ui, public-blocklist, edge-ops) and a healthy Postgres (the seven services with `PG_HOST`; Postgres gained a `pg_isready` healthcheck). Previously a service that started first silently kept a private in-memory blocklist (so admin-ui could not see the engine's blocks) or ran without Postgres (for example the tarpit lost its corpus) (#67).

## [0.1.5] - 2026-11-20

### Fixed

- Load the origin robots.txt into Rust escalation decisions; give violations
  +0.6 evidence and an independent block action that model output cannot dilute.
  Package/mount the policy and report robots violations separately from legacy
  sensitive-path hints.
- Block configured scraper/scanner/AI-crawler product tokens on the first request,
  with narrow configured exceptions that cannot bypass robots rules or exempt
  other tool tokens. Remove bare bot/crawler matches from bad-UA classification.
- Quote the sample environment's multiword WebAuthn RP name, validate shell
  sourcing in CI, and authenticate the documented escalation examples in both
  PowerShell and curl. Explain loading generated API keys into the terminal.

### Changed

- Updated compatible Rust dependencies.

### Security

- Update the locked quinn-udp dependency from 0.5.15 to 0.5.16 for
  RUSTSEC-2026-0538; add a CI regression floor for the patched version ranges.

## [0.1.4] - 2026-11-02

### Added

- Added authenticated incident evaluation, cooldown-limited admin webhook
  alerts, and manual Cloudflare and health-gated failover guidance.

### Changed

- Updated Redis, OpenTelemetry, and release action pins while retaining Rust 1.88 compatibility.

### Security

- Updated locked `ctutils` to resolve its RustSec advisory and retained the
  patched `tokio` release.

## [0.1.3] - 2026-10-22

### Fixed

- Restored native release bundle publication by providing the required
  CAPTCHA token secret during the packaged service smoke test.

## [0.1.2] - 2026-10-22

### Security

- Escaped tarpit request paths in HTML, rejected client-asserted verified bot
  identity, and normalized encoded sensitive paths during scoring.
- Bounded CAPTCHA state and public MFA attempts, made TOTP verification
  read-only for unknown users, and rejected local or trusted addresses in
  authenticated public blocklist reports, including IPv4-compatible forms.

### Changed

- Updated Rust dependencies and pinned GitHub Actions; the locked rustls
  dependency includes fixes for the reported RustSec advisories.
- Hardened service configuration, credentials, authentication, error handling,
  and MCP WebSocket response validation.

## [0.1.1] - 2026-10-21

### Fixed

- Normalize equivalent IPv6 spellings and IPv4-mapped addresses in blocklist
  and trust decisions. Existing Redis blocklist entries are canonicalized at
  service startup; stop older writers before rolling out the new version.
- Reject invalid flag actions instead of acknowledging a change that was not
  applied.
- Update vulnerable TLS, HTTP/2, QUIC, and other locked dependencies identified
  by the RustSec audit.

### Security

- Require the configured API key on public blocklist reports and reject
  malformed report content (GHSA-vgfc-ffwp-vv38).
- Review and dismiss deterministic test-only key findings with documented
  rationale.
