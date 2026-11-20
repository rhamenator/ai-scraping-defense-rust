#!/usr/bin/env python3
"""Prevent reintroducing quinn-udp versions affected by RUSTSEC-2026-0538."""
import os
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DependencyFloorTests(unittest.TestCase):
    def test_quinn_udp_is_in_a_patched_range(self):
        # https://rustsec.org/advisories/RUSTSEC-2026-0538.html
        path = Path(os.environ.get("ASD_LOCKFILE_UNDER_TEST", ROOT / "Cargo.lock"))
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for package in data.get("package", []):
            if package["name"] == "quinn-udp":
                version = tuple(int(part) for part in package["version"].split("."))
                self.assertTrue(
                    (0, 5, 16) <= version < (0, 6, 0) or version >= (0, 6, 3),
                    f"quinn-udp {package['version']} is below the RustSec patched ranges",
                )


if __name__ == "__main__":
    unittest.main()
