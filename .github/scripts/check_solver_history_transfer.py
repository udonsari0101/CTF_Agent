"""Round-trip regression for v2 solver log transfer."""

import json
import shutil
import sys
import tempfile
import time
import uuid
import zipfile
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.db import Settings, connect, initialize
from ctf_agent.solver_exchange import SCHEMA, SolverExchangeCoordinator
from ctf_agent.storage_layout import StorageLayout
from ctf_agent.workspace_transfer import (
    TransferError, export_challenge, export_workspace, import_challenge,
    import_workspace, preview_bundle,
)


def uid():
    return uuid.uuid4().hex


def main():
    with tempfile.TemporaryDirectory() as root:
        root = Path(root)
        settings = Settings(root / "data", root / "db", root / "config", root / "logs",
                            storage_min_free_bytes=0, auth_mode="nologin")
        initialize(settings)
        with closing(connect(settings)) as db, db:
            db.executescript(SCHEMA)
            owner = db.execute("SELECT id FROM users LIMIT 1").fetchone()[0]
            ws, ch, job, followup_job, orphan_job, guidance = uid(), uid(), uid(), uid(), uid(), uid()
            source_account = "source_account_" + uid()
            db.execute(
                "INSERT INTO workspaces(id,name,description,flag_format,open_challenge_after_create,created_at,updated_at,owner_user_id) VALUES(?,?,?,?,?,?,?,?)",
                (ws, "Transfer Test", "", None, 0, "2026-01-01", "2026-01-01", owner),
            )
            db.execute(
                "INSERT INTO challenges(id,workspace_id,name,category,description,status,previous_status,completion_source,flag,notes,remote,remote_mode,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ch, ws, "Test", "misc", "problem", "stopped", None, None, None, "", "", "none", "2026-01-01", "2026-01-01"),
            )
            now = time.time()
            db.execute(
                "INSERT INTO solver_jobs(id,owner_user_id,workspace_id,challenge_id,account_id,account_label,provider,model,reasoning_effort,status,created_at,updated_at,last_event_sequence,agents_json,context_usage_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job, owner, ws, ch, source_account, "account label", "codex", "gpt-6-sol", "ultra", "running", now - 80, now,
                 1,
                 json.dumps([{"id":"child","parent_id":"root","label":"Child","status":"running"}]),
                 json.dumps({"root":{"used_tokens":100,"window_tokens":1000}})),
            )
            event = {"protocol": 1, "job_id": job, "sequence": 1, "kind": "status", "status": "running", "created_at": now - 70}
            db.execute(
                "INSERT INTO solver_job_events(job_id,sequence,kind,event_json,created_at) VALUES(?,?,?,?,?)",
                (job, 1, "status", json.dumps(event), now - 70),
            )
            db.execute(
                "INSERT INTO solver_job_guidance(id,job_id,owner_user_id,message,requested_delivery,status,created_at) VALUES(?,?,?,?,?,?,?)",
                (guidance, job, owner, "Try another path", "next_turn", "queued", now - 20),
            )
            db.execute(
                "INSERT INTO solver_jobs(id,owner_user_id,workspace_id,challenge_id,account_id,account_label,provider,model,reasoning_effort,status,created_at,updated_at,continuation_mode,continuation_source_job_id,source_solver_job_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (followup_job, owner, ws, ch, source_account, "account label", "codex", "gpt-6-sol", "ultra", "completed", now - 10, now,
                 "session", job, job),
            )
            db.execute(
                "INSERT INTO solver_jobs(id,owner_user_id,workspace_id,challenge_id,account_id,account_label,provider,model,reasoning_effort,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (orphan_job, owner, ws, uid(), source_account, "account label", "codex", "gpt-6-sol", "low", "cancelled", now - 10, now),
            )
            db.commit()
        @contextmanager
        def database():
            with closing(connect(settings)) as db, db:
                yield db

        layout = StorageLayout(settings, database)
        whole = root / "whole.zip"
        exported = export_workspace(settings, layout, owner, ws, whole)
        assert exported["solver_job_count"] == 2 and exported["solver_event_count"] == 1
        preview = preview_bundle(whole, settings=settings, owner_user_id=owner)
        assert preview["version"] == 2 and preview["solver_job_count"] == 2
        real_disk_usage = shutil.disk_usage
        with patch("ctf_agent.workspace_transfer.shutil.disk_usage",
                   side_effect=lambda path: SimpleNamespace(free=0) if Path(path) == settings.db_dir else real_disk_usage(path)):
            assert preview_bundle(whole, settings=settings, owner_user_id=owner)["sufficient_space"] is False
            try:
                import_workspace(settings, layout, owner, whole, source_upload_id=uid())
                raise AssertionError("history import ignored database space")
            except TransferError as exc:
                assert "database space" in str(exc)
        with zipfile.ZipFile(whole) as bundle:
            assert source_account.encode() not in bundle.read("solver-history.jsonl")
        upload_id = uid()
        imported = import_workspace(settings, layout, owner, whole, source_upload_id=upload_id)
        assert imported == import_workspace(settings, layout, owner, whole, source_upload_id=upload_id)
        imported_challenge = imported["challenge_ids"][ch]
        with closing(connect(settings)) as db, db:
            historical = db.execute("SELECT * FROM solver_jobs WHERE challenge_id=? AND status='cancelled'", (imported_challenge,)).fetchone()
            assert historical and historical["id"] != job
            assert historical["status"] == "cancelled" and historical["imported_historical"] == 1
            assert historical["released_ingested"] == 1 and historical["account_id"].startswith("history_")
            assert historical["retry_checkpoint_json"] is None and historical["solver_artifact_json"] is None
            assert historical["owner_user_id"] == owner and historical["workspace_id"] == imported["workspace_id"]
            assert json.loads(historical["agents_json"])[0]["id"] == "child"
            assert json.loads(historical["context_usage_json"])["root"]["used_tokens"] == 100
            copied = db.execute("SELECT * FROM solver_job_events WHERE job_id=?", (historical["id"],)).fetchone()
            assert copied and json.loads(copied["event_json"])["job_id"] == historical["id"]
            instruction = db.execute("SELECT * FROM solver_job_guidance WHERE job_id=?", (historical["id"],)).fetchone()
            assert instruction and instruction["status"] == "rejected" and instruction["error_code"] == "imported_history"
            assert db.execute("SELECT COUNT(*) FROM solver_slots WHERE job_id=?", (historical["id"],)).fetchone()[0] == 0
            continuation = db.execute("SELECT * FROM solver_jobs WHERE challenge_id=? AND status='completed'", (imported_challenge,)).fetchone()
            assert continuation and continuation["continuation_source_job_id"] == historical["id"]
            assert continuation["id"] != followup_job and continuation["imported_historical"] == 1
        coordinator = SolverExchangeCoordinator(
            settings.database_path, settings.data_dir, settings.data_dir / "accounts",
            settings.data_dir / "solver-exchange", accept_new_jobs=False,
            enforce_host_ownership=False,
        )
        shown = coordinator.get(historical["id"], owner)
        assert shown["read_only_history"] and not shown["guidance_allowed"]
        assert not shown["input_ready_to_retry"] and shown["events"][0]["job_id"] == historical["id"]
        single = root / "single.zip"
        export_challenge(settings, layout, owner, ws, ch, single)
        imported_single = import_challenge(settings, layout, owner, imported["workspace_id"], single, source_upload_id=uid())
        assert imported_single["solver_job_count"] == 2
        with closing(connect(settings)) as db, db:
            assert db.execute("SELECT COUNT(*) FROM solver_jobs WHERE challenge_id=? AND imported_historical=1", (imported_single["challenge_id"],)).fetchone()[0] == 2
        # A v1 bundle remains readable. Removing the v2 history section makes
        # the old manifest shape and preserves all challenge/file data.
        legacy = root / "legacy.zip"
        with zipfile.ZipFile(single) as source, zipfile.ZipFile(legacy, "w", allowZip64=True) as target:
            manifest = json.loads(source.read("manifest.json"))
            manifest["version"] = 1
            manifest.pop("solver_history")
            for name in source.namelist():
                if name == "solver-history.jsonl":
                    continue
                target.writestr(name, json.dumps(manifest).encode() if name == "manifest.json" else source.read(name))
        assert preview_bundle(legacy)["version"] == 1
        old = import_challenge(settings, layout, owner, imported["workspace_id"], legacy, source_upload_id=uid())
        assert old["solver_job_count"] == 0
        # Corrupted history must not publish another challenge or session.
        corrupt = root / "corrupt.zip"
        with zipfile.ZipFile(single) as source, zipfile.ZipFile(corrupt, "w", allowZip64=True) as target:
            for name in source.namelist():
                data = source.read(name)
                target.writestr(name, data + b"x" if name == "solver-history.jsonl" else data)
        with closing(connect(settings)) as db:
            before = db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
        try:
            import_challenge(settings, layout, owner, imported["workspace_id"], corrupt, source_upload_id=uid())
            raise AssertionError("corrupted log was imported")
        except TransferError:
            pass
        with closing(connect(settings)) as db:
            after = db.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
        assert before == after
        print("v2 workspace/challenge round trip, read-only history, v1 compatibility, corruption rollback: passed")


if __name__ == "__main__":
    main()
