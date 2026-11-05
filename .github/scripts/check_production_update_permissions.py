"""Regression check for the host updater's version marker permissions."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("production_update", ROOT / "deploy" / "production-update.py")
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


with tempfile.TemporaryDirectory() as temporary:
    control = Path(temporary)
    marker = control / "current-version.json"
    payload = {"tag": "v0.4.40", "revision": "a" * 40, "repository": "owner/project"}

    original_umask = os.umask(0o077)
    try:
        helper._write_json(control, marker.name, payload)
    finally:
        os.umask(original_umask)

    assert stat.S_IMODE(marker.stat().st_mode) == 0o644
    assert json.loads(marker.read_text(encoding="utf-8")) == payload

    original_umask = os.umask(0o000)
    try:
        helper._write_json(control, marker.name, payload, mode=0o600)
    finally:
        os.umask(original_umask)

    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert json.loads(marker.read_text(encoding="utf-8")) == payload
    assert sorted(path.name for path in control.iterdir()) == [marker.name]

print("Production update marker permissions: OK")
