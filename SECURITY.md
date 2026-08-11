# Security Policy

## Supported code

Security fixes target the `master` branch and the most recent tagged release. Backports to older releases are best effort. Users should upgrade to the newest available release or container image.

## Reporting a vulnerability

Do not open a public issue or pull request containing vulnerability details.

1. Open a [private GitHub security advisory](https://github.com/rhamenator/ai-scraping-defense-rust/security/advisories/new).
2. If private reporting is unavailable, email **rhamenator@gmail.com**.
3. Include the affected version or commit, environment, reproduction steps, impact, and any suggested mitigation.
4. Remove unrelated credentials, personal data, and production secrets from the report.

We aim to acknowledge reports within 72 hours, provide status updates during triage, and coordinate disclosure after affected users have a reasonable opportunity to update.

## Research guidelines

Use test systems and your own data. Avoid privacy violations, service disruption, persistence, social engineering, and access beyond what is necessary to demonstrate the issue. Stop testing and report immediately if you encounter sensitive data.

## Operational security

Use unique production secrets, restrict network exposure, keep dependencies and images current, and review logs and diagnostic artifacts before sharing them publicly.
