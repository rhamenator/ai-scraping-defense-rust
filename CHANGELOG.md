# Changelog

## [Unreleased]

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
