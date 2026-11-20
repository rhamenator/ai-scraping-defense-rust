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
    def test_redis_clients_wait_for_a_healthy_redis(self):
        # Each service picks Redis or an in-memory store once at startup, so a service that
        # starts before Redis accepts connections would keep a private blocklist forever.
        compose = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
        blocks = re.split(r"(?m)^  (?=[a-z][a-z-]*:\n)", compose.split("\nservices:\n", 1)[1])
        checked = 0
        for block in blocks:
            name = block.split(":", 1)[0]
            if "REDIS_HOST: redis" in block:
                checked += 1
                self.assertRegex(
                    block,
                    r"depends_on:\n      redis:\n        condition: service_healthy",
                    name,
                )
        self.assertGreaterEqual(checked, 5)

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
