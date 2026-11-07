"""Static assets must not leave legacy JavaScript cached across a release."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.main import create_app


class StaticAssetCacheTest(unittest.TestCase):
    def test_release_assets_and_legacy_path(self):
        revision = "a" * 40
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary, patch.dict(
            os.environ, {"CTF_RELEASE_SHA": revision}
        ):
            root = Path(temporary)
            settings = Settings(root / "data", root / "db", root / "config", root / "logs",
                                storage_min_free_bytes=0, auth_mode="password")
            with TestClient(create_app(settings)) as client:
                index = client.get("/")
                self.assertEqual(index.status_code, 200)
                self.assertEqual(index.headers.get("cache-control"), "no-store")
                self.assertIn(f'/assets/{revision}/app.js', index.text)

                # The dynamic Telegram module used this stable URL before it was
                # changed to a relative import. It must not retain old code.
                legacy = client.get("/assets/telegram.js")
                self.assertEqual(legacy.status_code, 200)
                self.assertEqual(legacy.headers.get("cache-control"), "no-store")

                versioned = client.get(f"/assets/{revision}/app.js")
                self.assertEqual(versioned.status_code, 200)
                self.assertNotEqual(versioned.headers.get("cache-control"), "no-store")

    def test_development_asset_path_is_not_cacheable(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary, patch.dict(
            os.environ, {"CTF_RELEASE_SHA": "dev"}
        ):
            root = Path(temporary)
            settings = Settings(root / "data", root / "db", root / "config", root / "logs",
                                storage_min_free_bytes=0, auth_mode="password")
            with TestClient(create_app(settings)) as client:
                response = client.get("/assets/dev/app.js")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers.get("cache-control"), "no-store")


if __name__ == "__main__":
    unittest.main()
