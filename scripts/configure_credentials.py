#!/usr/bin/env python3
"""Interactively configure local service credentials in .env."""

from __future__ import annotations

import getpass
import secrets
from pathlib import Path


CREDENTIALS = (
    "WEBHOOK_SHARED_SECRET",
    "CAPTCHA_TOKEN_SECRET",
    "ESCALATION_API_KEY",
    "INCIDENT_EVALUATOR_API_KEY",
    "CLOUD_DASHBOARD_API_KEY",
    "CLOUD_PROXY_API_KEY",
    "PROMPT_ROUTER_API_KEY",
    "ADMIN_API_KEY",
    "PUBLIC_BLOCKLIST_API_KEY",
    "PAY_PER_CRAWL_API_KEY",
    "EDGE_OPS_API_KEY",
    "RAG_TRAINER_API_KEY",
    "JWT_SECRET",
    "REDIS_PASSWORD",
    "PG_PASSWORD",
)


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def write_env(path: Path, values: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    remaining = dict(values)
    output: list[str] = []
    for line in lines:
        if line and not line.lstrip().startswith("#") and "=" in line:
            key = line.split("=", 1)[0]
            if key in remaining:
                output.append(f"{key}={remaining.pop(key)}\n")
                continue
        output.append(line)
    if output and not output[-1].endswith("\n"):
        output[-1] += "\n"
    output.extend(f"{key}={value}\n" for key, value in remaining.items())
    path.write_text("".join(output), encoding="utf-8")
    path.chmod(0o600)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    env_path = root / ".env"
    sample_path = root / "config" / "sample.env"
    if not env_path.exists():
        env_path.write_text(sample_path.read_text(encoding="utf-8"), encoding="utf-8")
    current = read_env(env_path)
    updates: dict[str, str] = {}
    print("Configure credentials. Leave blank to generate a strong random value.")
    for key in CREDENTIALS:
        existing = current.get(key, "")
        keepable = existing if len(existing) >= 32 else ""
        while True:
            prompt = f"{key} [{'keep existing' if keepable else 'generate'}]: "
            entered = getpass.getpass(prompt).strip()
            value = entered or keepable or secrets.token_urlsafe(36)
            if len(value) >= 32:
                updates[key] = value
                break
            print(f"{key} must contain at least 32 characters.")
    write_env(env_path, updates)
    print(f"Credentials written to {env_path} with owner-only permissions.")
    print("Start the stack with: docker compose --env-file .env up --build")


if __name__ == "__main__":
    main()
