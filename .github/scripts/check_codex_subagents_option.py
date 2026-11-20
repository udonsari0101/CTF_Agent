"""Offline regression for persisted Codex delegation across reasoning levels."""

from __future__ import annotations

import json
import sys
import tempfile
import uuid
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings, connect, initialize  # noqa: E402
from ctf_agent.solver import ModelConfiguration  # noqa: E402
from ctf_agent.solver_exchange import SCHEMA, ExchangeError, SolverExchangeCoordinator  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory() as root_name:
        root = Path(root_name)
        settings = Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        initialize(settings)
        with closing(connect(settings)) as db, db:
            owner = db.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
            workspace = uuid.uuid4().hex
            account = uuid.uuid4().hex
            db.execute(
                """INSERT INTO workspaces
                   (id,name,description,flag_format,open_challenge_after_create,
                    created_at,updated_at,owner_user_id)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (workspace, "Delegation", "", None, 0, "2026-01-01", "2026-01-01", owner),
            )
            db.execute(
                """CREATE TABLE provider_accounts (
                   id TEXT PRIMARY KEY,provider TEXT NOT NULL,label TEXT NOT NULL,
                   selected INTEGER NOT NULL,model TEXT,reasoning_effort TEXT,
                   snapshot TEXT,checked_at REAL,created_at REAL NOT NULL,
                   owner_user_id TEXT NOT NULL,service_tier TEXT,ultracode INTEGER NOT NULL DEFAULT 0,
                   auth_kind TEXT NOT NULL DEFAULT 'oauth')"""
            )
            db.execute(
                """CREATE TABLE account_lifecycle_blocks (
                   owner_user_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,started_at REAL NOT NULL)"""
            )
            db.execute(
                """INSERT INTO provider_accounts
                   (id,provider,label,selected,model,reasoning_effort,snapshot,created_at,owner_user_id)
                   VALUES(?,'codex','test',1,'gpt-6-sol','xhigh',?,1,?)""",
                (account, json.dumps({"status": "authenticated"}), owner),
            )
        coordinator = SolverExchangeCoordinator(
            settings.database_path, settings.data_dir, settings.data_dir / "accounts",
            settings.data_dir / "solver-exchange", enforce_host_ownership=False,
        )
        cases = (("low", True, True), ("medium", True, True),
                 ("xhigh", False, False), ("ultra", None, True),
                 ("ultra", False, False))
        for effort, requested, expected in cases:
            challenge = uuid.uuid4().hex
            with closing(connect(settings)) as db, db:
                db.execute(
                    """INSERT INTO challenges
                       (id,workspace_id,name,category,description,status,previous_status,
                        completion_source,flag,notes,remote,remote_mode,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (challenge, workspace, f"{effort}-{requested}", "misc", "sample",
                     "stopped", None, None, None, "", "", "none", "2026-01-01", "2026-01-01"),
                )
            job = coordinator.enqueue(
                owner, workspace, challenge, provider="codex", expected_account_id=account,
                configuration_override=ModelConfiguration("codex", "gpt-6-sol", effort),
                subagents_enabled=requested,
            )
            assert job["subagents_enabled"] is expected, job
            assert job["configuration"]["subagents_enabled"] is expected, job
            with closing(connect(settings)) as db:
                saved = db.execute(
                    "SELECT subagents_enabled FROM solver_jobs WHERE id=?", (job["id"],)
                ).fetchone()[0]
                assert saved == int(expected)
        try:
            coordinator.enqueue(
                owner, workspace, challenge, provider="claude", subagents_enabled=True,
            )
        except ExchangeError as error:
            assert error.code == "invalid_subagents_setting"
        else:
            raise AssertionError("Claude accepted Codex-only delegation")
        migration_root = root / "pre-option-installation"
        old_settings = Settings(
            migration_root / "data", migration_root / "db",
            migration_root / "config", migration_root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        initialize(old_settings)
        column = "    subagents_enabled INTEGER NOT NULL DEFAULT 0 CHECK(subagents_enabled IN (0,1)),\n"
        assert column in SCHEMA
        with closing(connect(old_settings)) as db, db:
            db.executescript(SCHEMA.replace(column, ""))
            for effort in ("ultra", "xhigh"):
                db.execute(
                    """INSERT INTO solver_jobs
                       (id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                        model,reasoning_effort,status,created_at,updated_at)
                       VALUES(?,?,?,?,?,'codex','gpt-6-sol',?,'failed',1,1)""",
                    (uuid.uuid4().hex, "owner", "workspace", uuid.uuid4().hex, "account", effort),
                )
        SolverExchangeCoordinator(
            old_settings.database_path, old_settings.data_dir,
            old_settings.data_dir / "accounts", old_settings.data_dir / "solver-exchange",
            enforce_host_ownership=False,
        )
        with closing(connect(old_settings)) as db:
            historical = dict(db.execute(
                "SELECT reasoning_effort,subagents_enabled FROM solver_jobs"
            ).fetchall())
            assert historical == {"ultra": 1, "xhigh": 0}, historical
        print("Codex delegation persisted for low/medium/xhigh/ultra and rejected for Claude: passed")


if __name__ == "__main__":
    main()
