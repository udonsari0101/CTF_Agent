"""Authenticate isolated no-login API fixtures without a password prompt."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient as FastAPITestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ctf_agent.local_access import KEY_NAME


class TestClient(FastAPITestClient):
    def __init__(self, app, *args, **kwargs):
        super().__init__(app, *args, **kwargs)
        if app.state.settings.auth_mode == "nologin":
            token = (app.state.settings.config_dir / KEY_NAME).read_text(encoding="ascii").strip()
            ticket = self.post("/api/auth/local/ticket", json={"token": token})
            if ticket.status_code != 200:
                raise AssertionError("Local test browser ticket request failed")
            response = self.post("/api/auth/local/bootstrap", json={"ticket": ticket.json()["ticket"]})
            if response.status_code != 200:
                raise AssertionError("Local test browser bootstrap failed")
