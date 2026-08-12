#!/usr/bin/env python3
"""Package native service binaries produced by a GitHub Actions runner."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import tarfile
import zipfile
from pathlib import Path


SERVICES = (
    "admin-ui",
    "ai-service",
    "captcha-service",
    "cloud-dashboard",
    "cloud-proxy",
    "config-recommender",
    "edge-ops",
    "escalation-engine",
    "pay-per-crawl",
    "prompt-router",
    "public-blocklist",
    "rag-trainer",
    "tarpit-api",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--suffix", default="")
    args = parser.parse_args()

    prefix = f"ai-scraping-defense-rust-{args.version}-{args.platform}"
    artifacts = Path("artifacts")
    stage = artifacts / prefix
    binary_root = Path("target") / args.target / "release"
    stage.mkdir(parents=True, exist_ok=True)

    for service in SERVICES:
        source = binary_root / f"{service}{args.suffix}"
        if not source.is_file():
            raise FileNotFoundError(f"release binary was not produced: {source}")
        shutil.copy2(source, stage / source.name)

    shutil.copy2("README.md", stage / "README.md")
    shutil.copy2("docs/USAGE.md", stage / "USAGE.md")
    shutil.copy2("config/sample.env", stage / "sample.env")
    shutil.copy2("Cargo.lock", stage / "Cargo.lock")

    if args.platform.startswith("windows-"):
        archive = artifacts / f"{prefix}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(artifacts))
    else:
        archive = artifacts / f"{prefix}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(stage, arcname=prefix)

    checksum = archive.with_name(f"{archive.name}.sha256")
    checksum.write_text(f"{sha256(archive)} *{archive.name}\n", encoding="ascii")


if __name__ == "__main__":
    main()
