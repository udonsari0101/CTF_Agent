"""An explicit offline answer resumes the exact blocked solve checkpoint."""

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
from ctf_agent.solver_exchange import ExchangeError, SolverExchangeCoordinator  # noqa: E402
from ctf_agent.solver_retry import encode_checkpoint, merge_continuation  # noqa: E402


def rejected_code(call, expected: str) -> None:
    try:
        call()
    except ExchangeError as error:
        assert error.code == expected, error.code
    else:
        raise AssertionError(f"expected {expected}")


def main() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        settings = Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        initialize(settings)
        owner = workspace = challenge = account = ""
        with closing(connect(settings)) as db, db:
            owner = db.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
            workspace, challenge, account = (uuid.uuid4().hex for _ in range(3))
            db.execute(
                """INSERT INTO workspaces
                   (id,name,description,flag_format,open_challenge_after_create,
                    created_at,updated_at,owner_user_id)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (workspace, "Offline", "", None, 0, "2026-01-01", "2026-01-01", owner),
            )
            db.execute(
                """INSERT INTO challenges
                   (id,workspace_id,name,category,description,status,previous_status,
                    completion_source,flag,notes,remote,remote_mode,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (challenge, workspace, "Local binary", "rev", "Inspect the artifact",
                 "pending", None, None, None, "", "", "none", "2026-01-01", "2026-01-01"),
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
        enqueue = lambda **extra: coordinator.enqueue(  # noqa: E731
            owner, workspace, challenge, provider="codex", expected_account_id=account,
            configuration_override=ModelConfiguration("codex", "gpt-6-sol", "xhigh"),
            **extra,
        )
        rejected_code(lambda: enqueue(confirm_no_remote=True), "remote_confirmation_unavailable")
        first = enqueue()
        assert coordinator.get(first["id"], owner)["confirm_no_remote_eligible"] is False
        with closing(connect(settings)) as db, db:
            source = db.execute(
                "SELECT challenge_input_sha256,challenge_base_sha256 FROM solver_jobs WHERE id=?",
                (first["id"],),
            ).fetchone()
            checkpoint = encode_checkpoint(merge_continuation(
                None, "Observed local decompiler result; next test pending.", "needs_remote"
            ))
            db.execute(
                """UPDATE solver_jobs SET status='needs_input',released_ingested=1,
                   error_json=? WHERE id=?""",
                (json.dumps({"code": "remote_input_required", "message": "Need remote"}), first["id"]),
            )
            db.execute("UPDATE challenges SET status='stopped' WHERE id=?", (challenge,))
            db.execute(
                """INSERT INTO solver_retry_checkpoints
                   (challenge_id,workspace_id,owner_user_id,checkpoint_json,input_sha256,
                    base_input_sha256,source_remote_mode,source_job_id,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (challenge, workspace, owner, checkpoint, source["challenge_input_sha256"],
                 source["challenge_base_sha256"], "none", first["id"], 1, 1),
            )
        rejected_code(enqueue, "remote_input_required")
        assert coordinator.get(first["id"], owner)["confirm_no_remote_eligible"] is True
        with closing(connect(settings)) as db, db:
            db.execute("UPDATE solver_jobs SET imported_historical=1 WHERE id=?", (first["id"],))
        assert coordinator.get(first["id"], owner)["confirm_no_remote_eligible"] is False
        rejected_code(lambda: enqueue(confirm_no_remote=True), "remote_confirmation_unavailable")
        with closing(connect(settings)) as db, db:
            db.execute("UPDATE solver_jobs SET imported_historical=0 WHERE id=?", (first["id"],))
        resumed = enqueue(confirm_no_remote=True)
        assert resumed["remote_absence_confirmed"] is True
        assert resumed["continuation_source_job_id"] == first["id"]
        assert resumed["continuation_mode"] in {"checkpoint", "workspace", "session"}
        assert coordinator.get(first["id"], owner)["confirm_no_remote_eligible"] is False
        with closing(connect(settings)) as db:
            row = db.execute(
                "SELECT remote_absence_confirmed,retry_checkpoint_json FROM solver_jobs WHERE id=?",
                (resumed["id"],),
            ).fetchone()
            assert row["remote_absence_confirmed"] == 1
            assert row["retry_checkpoint_json"] == checkpoint
    print("Explicit no-remote answer resumes the exact checkpoint: passed")


if __name__ == "__main__":
    main()
