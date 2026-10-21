# Changelog

## [Unreleased]

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

- Review and dismiss deterministic test-only key findings with documented
  rationale.
