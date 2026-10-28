# Changelog

## [Unreleased]

### Added

- Added authenticated incident evaluation, cooldown-limited admin webhook
  alerts, and manual Cloudflare and health-gated failover guidance.

### Security

- Updated locked `ctutils` and `tokio` dependencies to resolve RustSec audit
  findings.

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
