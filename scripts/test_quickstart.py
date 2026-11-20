#!/usr/bin/env python3
"""Regress the documented quick-start contract using only the standard library."""
import re
import runpy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class QuickstartTests(unittest.TestCase):
    def test_services_that_hold_the_blocklist_receive_the_block_lifetime(self):
        compose = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
        holders = compose.count('REDIS_DB_BLOCKLIST: "0"')
        passed = compose.count('BLOCKLIST_TTL_SECONDS: "${BLOCKLIST_TTL_SECONDS:-86400}"')
        self.assertGreater(holders, 0)
        self.assertEqual(holders, passed)

    def test_redis_and_postgres_clients_wait_for_healthy_backends(self):
        # Each service picks Redis/Postgres or a fallback once at startup, so a service that
        # starts before the backend accepts connections would run degraded for its lifetime.
        compose = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
        blocks = re.split(r"(?m)^  (?=[a-z][a-z-]*:\n)", compose.split("\nservices:\n", 1)[1])
        checked = {"redis": 0, "postgres": 0}
        for block in blocks:
            name = block.split(":", 1)[0]
            for backend, marker in (("redis", "REDIS_HOST: redis"), ("postgres", "PG_HOST: postgres")):
                if marker in block:
                    checked[backend] += 1
                    self.assertRegex(
                        block,
                        rf"depends_on:(?:\n(?:      \w+:\n        condition: service_healthy))*?\n      {backend}:\n        condition: service_healthy",
                        f"{name} must wait for {backend}",
                    )
        self.assertGreaterEqual(checked["redis"], 5)
        self.assertGreaterEqual(checked["postgres"], 7)
        self.assertIn("pg_isready", compose)

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell unavailable")
    def test_sample_env_can_be_sourced_and_strips_value_quotes(self):
        result = subprocess.run(
            [
                "sh",
                "-eu",
                "-c",
                "set -a; . ./config/sample.env; "
                'test "$ADMIN_UI_WEBAUTHN_RP_NAME" = "AI Scraping Defense Admin"',
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell unavailable")
    def test_credential_writer_preserves_shell_safe_sample_values(self):
        helper = runpy.run_path(str(ROOT / "scripts/configure_credentials.py"))
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            env_path.write_text(
                (ROOT / "config/sample.env").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            helper["write_env"](env_path, {"ESCALATION_API_KEY": "regression-only"})
            result = subprocess.run(
                [
                    "sh",
                    "-eu",
                    "-c",
                    'set -a; . "$1"; '
                    'test "$ADMIN_UI_WEBAUTHN_RP_NAME" = "AI Scraping Defense Admin"',
                    "sh",
                    str(env_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_score_request_example_has_required_authentication(self):
        text = (ROOT / "docs/USAGE.md").read_text(encoding="utf-8")
        section = text.split("Score a request:", 1)[1].split("Block an IP", 1)[0]
        examples = re.findall(r"```(\w+)\n(.*?)```", section, re.DOTALL)
        self.assertTrue(examples, "missing score-request examples")
        for language, body in examples:
            with self.subTest(language=language):
                self.assertIn("x-api-key", body.lower())
                self.assertIn("ESCALATION_API_KEY", body)


if __name__ == "__main__":
    unittest.main()
