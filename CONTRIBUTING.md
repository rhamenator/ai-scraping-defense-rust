# Contributing

Thank you for contributing to AI Scraping Defense Rust.

## Choose the right channel

- Use the structured bug, feature, documentation, or support form when opening an issue.
- Read [SUPPORT.md](SUPPORT.md) before requesting usage help.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md); never put vulnerability details in a public issue.
- Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in all project interactions.

For substantial features, architectural changes, or compatibility changes, open an issue before investing in implementation.

## Development workflow

1. Fork the repository and create a focused branch from `master`.
2. Keep unrelated refactors out of behavior or security fixes.
3. Add or update tests for changed behavior.
4. Update operator documentation and `docs/PARITY.md` when compatibility changes.
5. Use short, present-tense commit messages.
6. Open a pull request and complete the PR template with exact validation results.

## Validation

Run the checks relevant to your change. The normal Rust baseline is:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

For deployment changes, also validate the affected Docker Compose, Kubernetes, Helm, or smoke-test path. Explain any check you could not run.

## Contribution requirements

- Preserve secure defaults and avoid logging secrets or sensitive request data.
- Keep public APIs and configuration backward compatible unless the change is explicitly documented as breaking.
- Do not commit generated build output, credentials, private data, or machine-specific configuration.
- Contributions are accepted under the repository's [GPL-3.0-or-later license](LICENSE).
