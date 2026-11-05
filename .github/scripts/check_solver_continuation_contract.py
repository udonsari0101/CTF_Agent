"""Offline continuation contract across native and provider-switch retries."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver_continuation import (  # noqa: E402
    WORKDIR_REL,
    capture_snapshot,
    read_input,
    restore_snapshot,
    stage_workspace_only,
    workspace_baseline,
)
from ctf_agent.solver import ModelConfiguration  # noqa: E402
from ctf_agent.solver_retry import RetryCheckpoint  # noqa: E402
from ctf_agent.db import SCHEMA as DATABASE_SCHEMA  # noqa: E402
from ctf_agent.solver_exchange import (  # noqa: E402
    SCHEMA as SOLVER_SCHEMA,
    _activity_checkpoint_summary,
    _related_evidence_context,
)
from ctf_agent.solver_worker import (  # noqa: E402
    AppServerFailure,
    ClaudePrintDriver,
    CodexAppServer,
    _bounded_soft_turn_outcome,
)

INPUT_SHA256 = "a" * 64
SESSION_ID = "12345678-1234-1234-1234-123456789abc"


class ContinuationContractTests(unittest.TestCase):
    def test_progress_only_detection_preserves_observed_facts(self) -> None:
        # Claude's structured private_notes pass through this detector.  A
        # false positive clears the notes before a later retry can inherit them.
        for observation in (
            "I will analyze the cipher. The key is 0x13; XOR each byte with it.",
            "I will inspect the service. The endpoint returned HTTP 403 for an invalid token.",
            "I will review the binary; its header specifies a 256-byte payload.",
            "I will inspect, got HTTP 403 from the endpoint.",
            "I will test; got an error from the parser.",
            "I will inspect the service.\nKey=0x13 matched the digest.",
        ):
            with self.subTest(observation=observation):
                self.assertIsNone(_bounded_soft_turn_outcome(
                    observation, command_execution_seen=False,
                ))
        for promise in (
            "I will check the attachment next.",
            "I will inspect the binary. Then I will test its parser.",
            "I will inspect the binary, and I will test its parser.",
        ):
            with self.subTest(promise=promise):
                self.assertEqual(_bounded_soft_turn_outcome(
                    promise, command_execution_seen=False,
                ), "progress_only")

    def test_rejected_flag_retry_keeps_offline_candidates_and_remote_modes_distinct(self) -> None:
        rejected = "CTF{rejected}"
        for mode, remote in (
            ("none", ""),
            ("unknown", ""),
            ("endpoint", "https://example.invalid/challenge"),
        ):
            for structured in (False, True):
                with self.subTest(remote_mode=mode, structured_discovery=structured):
                    self._check_rejected_flag_retry(mode, remote, structured, rejected)

    def _check_rejected_flag_retry(
        self, mode: str, remote: str, structured: bool, rejected: str,
    ) -> None:
        challenge = self.root / f"retry-{mode}-{structured}"
        (challenge / "notes").mkdir(parents=True)
        (challenge / "attachments").mkdir()
        artifact = challenge / "attachments" / "verified-flag.txt"
        artifact.write_text("CTF{artifact-verified}", encoding="utf-8")
        prompts: list[str] = []
        driver = object.__new__(CodexAppServer)
        driver.structured_discovery = structured
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-6-sol", "high"),
            remote_mode=mode,
            remote=remote,
            retry_checkpoint=RetryCheckpoint(
                revision=1, rejected_flags=(rejected,),
                private_notes="rejected candidate was a placeholder",
                prior_writeup="",
            ),
            max_reasoning_available=False,
            ultra_escalation_mode="off",
        )

        async def turn(_manifest, prompt, _schema, _cancelled, _progress):
            prompts.append(prompt)
            # Simulate submit-flag after checking the supplied artifact.
            candidate = artifact.read_text(encoding="utf-8")
            descriptor = os.open(
                challenge / ".flag-candidate", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
            )
            try:
                os.write(descriptor, candidate.encode("utf-8"))
            finally:
                os.close(descriptor)
            return (
                {"flag": candidate, "private_notes": "verified from artifact"}
                if structured else {}
            )

        async def progress(_state, **_details):
            return None

        driver._turn = turn
        result = asyncio.run(driver.run_discovery(
            manifest, challenge, asyncio.Event(), progress,
        ))
        self.assertEqual(result["flag"], "CTF{artifact-verified}")
        self.assertEqual(len(prompts), 1)
        self.assertIn("never resubmit it", prompts[0])
        self.assertIn("A local value may be genuine or a placeholder", prompts[0])
        self.assertNotIn("run solver.py against the remote", prompts[0])
        self.assertEqual(
            json.loads((challenge / "notes" / "POISON.json").read_text(encoding="utf-8"))[
                "rejected_flags"
            ],
            [rejected],
        )
        if mode == "none":
            self.assertIn("Configured remote state for this job: `none`", prompts[0])
            self.assertIn("do not assume a service exists", prompts[0])
        elif mode == "unknown":
            self.assertIn("Authoritative remote state for this job: `unknown`", prompts[0])
            self.assertIn("Do not invent or probe an endpoint", prompts[0])
        else:
            self.assertIn("Authoritative remote state for this job: `endpoint`", prompts[0])
            self.assertIn("Use the endpoint documented", prompts[0])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = self.root / "ctf-job-abcdef"
        self.old.mkdir()
        self.workdir = self.old / WORKDIR_REL
        (self.workdir / "notes").mkdir(parents=True)
        (self.workdir / "AGENTS.md").write_text("current manual", encoding="utf-8")
        (self.workdir / "notes" / "RELATED.json").write_text("{}", encoding="utf-8")
        (self.workdir / "original.bin").write_bytes(b"original input")
        self.baseline = workspace_baseline(self.workdir)
        self.assertIsNotNone(self.baseline)
        (self.workdir / "notes" / "ANALYSIS.md").write_text("verified observation", encoding="utf-8")
        (self.workdir / "solver.py").write_text("print('candidate')", encoding="utf-8")
        (self.workdir / ".remote-request").write_text("one-shot", encoding="utf-8")
        (self.workdir / "auth.json").write_text("private credential", encoding="utf-8")
        self.active = self.root / "active"
        self.active.mkdir()

    def _capture(self, provider: str) -> dict:
        if provider == "codex":
            history = self.old / "home" / "sessions" / "2026" / "11" / "04" / f"rollout-{SESSION_ID}.jsonl"
        else:
            history = self.old / "home" / "claude" / "projects" / "-challenge" / f"{SESSION_ID}.jsonl"
        history.parent.mkdir(parents=True)
        history.write_text('{"type":"message","content":"private transcript"}\n', encoding="utf-8")
        self.assertTrue(capture_snapshot(
            self.active, self.old, provider, SESSION_ID, INPUT_SHA256, self.baseline,
        ))
        meta = json.loads((self.active / "continuation" / "meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["session_id"], SESSION_ID)
        return meta

    def _stage(self, meta: dict, mode: str, provider: str) -> Path:
        staged = self.root / "staged"
        staged.mkdir()
        transfer = staged / "continuation-input"
        transfer.mkdir()
        source = self.active / "continuation" / "snapshot.tar.gz"
        if mode == "workspace":
            digest, size = stage_workspace_only(
                source, transfer / "snapshot.tar.gz",
                expected_size=meta["archive_size"], expected_sha256=meta["archive_sha256"],
                maximum_size=meta["archive_size"] + 65536, provider=provider,
            )
            meta = {**meta, "archive_sha256": digest, "archive_size": size, "session_id": ""}
        else:
            shutil.copyfile(source, transfer / "snapshot.tar.gz")
        (transfer / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        (transfer / "mode.json").write_text(json.dumps({"version": 1, "mode": mode}), encoding="utf-8")
        return staged

    def _new_root(self) -> Path:
        root = self.root / "retry" / self.old.name
        (root / WORKDIR_REL).mkdir(parents=True)
        return root

    def test_codex_native_resume_restores_history_and_work_without_private_files(self) -> None:
        meta = self._capture("codex")
        staged = self._stage(meta, "session", "codex")
        continuation = read_input(staged, "codex")
        self.assertEqual(continuation.mode, "session")
        new_root = self._new_root()
        self.assertTrue(restore_snapshot(staged, new_root, continuation))
        self.assertEqual((new_root / WORKDIR_REL / "notes" / "ANALYSIS.md").read_text(), "verified observation")
        self.assertEqual(len(list((new_root / "home" / "sessions").rglob("*.jsonl"))), 1)
        self.assertFalse((new_root / WORKDIR_REL / "auth.json").exists())
        self.assertFalse((new_root / WORKDIR_REL / ".remote-request").exists())
        self.assertFalse((new_root / WORKDIR_REL / "original.bin").exists())
        self.assertFalse((new_root / WORKDIR_REL / "AGENTS.md").exists())

    def test_cross_provider_handoff_carries_work_but_not_session_history(self) -> None:
        meta = self._capture("codex")
        staged = self._stage(meta, "workspace", "codex")
        continuation = read_input(staged, "claude")
        self.assertEqual(continuation.mode, "workspace")
        self.assertEqual(continuation.session_id, "")
        new_root = self._new_root()
        self.assertTrue(restore_snapshot(staged, new_root, continuation))
        self.assertEqual((new_root / WORKDIR_REL / "solver.py").read_text(), "print('candidate')")
        self.assertFalse((new_root / "home" / "sessions").exists())
        self.assertFalse((new_root / "home" / "claude").exists())

    def test_claude_native_resume_restores_project_session(self) -> None:
        meta = self._capture("claude")
        staged = self._stage(meta, "session", "claude")
        continuation = read_input(staged, "claude")
        new_root = self._new_root()
        self.assertTrue(restore_snapshot(staged, new_root, continuation))
        self.assertEqual(len(list((new_root / "home" / "claude" / "projects").rglob("*.jsonl"))), 1)

    def test_corrupt_archive_never_restores_partial_workspace(self) -> None:
        meta = self._capture("codex")
        staged = self._stage(meta, "session", "codex")
        archive = staged / "continuation-input" / "snapshot.tar.gz"
        with archive.open("ab") as stream:
            stream.write(b"corruption")
        new_root = self._new_root()
        self.assertFalse(restore_snapshot(staged, new_root, read_input(staged, "codex")))
        self.assertFalse((new_root / WORKDIR_REL / "solver.py").exists())

    def test_codex_native_resume_is_confirmed_only_after_matching_thread(self) -> None:
        driver = object.__new__(CodexAppServer)
        driver.thread_id = None
        driver.resume_thread_id = SESSION_ID
        driver.challenge = self.workdir
        events = []
        driver.continuation_event = events.append
        driver._sandbox_parameters = lambda *args, **kwargs: {"sandbox": "workspace-write"}
        seen = []

        async def request(method, params):
            seen.append((method, params))
            return {"thread": {"id": SESSION_ID, "ephemeral": False}}

        driver.request = request
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-6-sol", "high"),
            network_enabled=True,
        )
        self.assertEqual(asyncio.run(driver._thread(manifest)), SESSION_ID)
        self.assertEqual([item[0] for item in seen], ["thread/resume"])
        self.assertEqual(seen[0][1]["threadId"], SESSION_ID)
        self.assertEqual(events, ["session_resumed"])

    def test_codex_rejected_resume_keeps_workspace_and_starts_new_thread(self) -> None:
        driver = object.__new__(CodexAppServer)
        driver.thread_id = None
        driver.resume_thread_id = SESSION_ID
        driver.challenge = self.workdir
        events = []
        driver.continuation_event = events.append
        driver._sandbox_parameters = lambda *args, **kwargs: {"sandbox": "workspace-write"}
        driver.rate_limit_context = None
        seen = []

        async def request(method, params):
            seen.append(method)
            if method == "thread/resume":
                raise AppServerFailure({"code": "provider_session_not_found"})
            return {"thread": {"id": "new-thread"}, "model": "gpt-6-sol"}

        driver.request = request
        manifest = SimpleNamespace(
            configuration=ModelConfiguration("codex", "gpt-6-sol", "high"),
            network_enabled=True,
        )
        self.assertEqual(asyncio.run(driver._thread(manifest)), "new-thread")
        self.assertEqual(seen, ["thread/resume", "thread/start"])
        self.assertEqual(events, ["workspace_restored"])
        self.assertIsNone(driver.resume_thread_id)

    def test_claude_resume_rejection_retries_once_as_fresh_session(self) -> None:
        driver = ClaudePrintDriver(
            self.old / "home", self.workdir,
            ModelConfiguration("claude", "opus", "high"),
            expected_version="1.2.3", command_prefix=["claude"],
        )
        driver.resume_session_id = SESSION_ID
        events = []
        driver.continuation_event = events.append
        seen = []

        async def turn_once(manifest, prompt, schema, cancelled, progress):
            seen.append(driver.resume_session_id)
            if len(seen) == 1:
                raise AppServerFailure({"code": "provider_session_not_found"})
            return {"flag": "", "private_notes": "rechecked work"}

        driver._turn_once = turn_once
        manifest = SimpleNamespace(job_id="b" * 32)

        async def progress(*args, **kwargs):
            pass

        result = asyncio.run(driver._turn(manifest, "continue", {}, asyncio.Event(), progress))
        self.assertEqual(result["private_notes"], "rechecked work")
        self.assertEqual(seen, [SESSION_ID, None])
        self.assertEqual(events, ["workspace_restored"])
        self.assertTrue(driver.resume_fallback_attempted)

    def test_checkpoint_summary_keeps_bounded_subagent_observations(self) -> None:
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute(
            "CREATE TABLE solver_job_events("
            "job_id TEXT, sequence INTEGER, kind TEXT, event_json TEXT, created_at REAL)"
        )
        job_id = "c" * 32
        events = [
            {"kind": "activity", "phase": "completed", "tool": "analysis",
             "agent_id": "root", "message": "root hypothesis"},
            *(
                {"kind": "activity", "phase": "completed", "tool": "analysis",
                 "agent_id": "child-a", "message": f"child finding {index}"}
                for index in range(20)
            ),
        ]
        db.executemany(
            "INSERT INTO solver_job_events VALUES(?,?,?,?,?)",
            ((job_id, index, "activity", json.dumps(event), index)
             for index, event in enumerate(events, 1)),
        )
        summary = _activity_checkpoint_summary(db, job_id)
        self.assertIn("root hypothesis", summary)
        self.assertIn("Subagent child-a Model observation", summary)
        self.assertEqual(summary.count("Subagent child-a"), 8)
        self.assertLessEqual(len(summary.encode("utf-8")), 12 * 1024)

    def test_linked_evidence_requires_opt_in_current_source_and_accepted_flag(self) -> None:
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        db.executescript(DATABASE_SCHEMA)
        db.execute("ALTER TABLE workspaces ADD COLUMN owner_user_id TEXT")
        db.executescript(SOLVER_SCHEMA)
        db.execute("INSERT INTO users(id,username,password_hash,role,created_at) "
                   "VALUES('owner','owner','hash','admin','now')")
        db.execute("INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) "
                   "VALUES('workspace','workspace','now','now','owner')")
        for challenge_id, name, flag in (
            ("target", "Target", None), ("source", "Source", "CTF{accepted}"),
        ):
            db.execute(
                """INSERT INTO challenges(id,workspace_id,name,category,description,
                     status,completion_source,flag,notes,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (challenge_id, "workspace", name, "web", "private description",
                 "solved" if challenge_id == "source" else "pending",
                 "agent" if challenge_id == "source" else None, flag,
                 "private source notes", "now", "revision-1"),
            )
        db.execute("INSERT INTO challenge_relations VALUES('workspace','source','target','now')")
        self.assertEqual(_related_evidence_context(db, "owner", "workspace", "target"), "")
        db.execute(
            """INSERT INTO challenge_evidence_shares
               (workspace_id,target_challenge_id,source_challenge_id,
                observation,include_flag,source_updated_at,verified_by_user_id,verified_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            ("workspace", "target", "source", "The boundary check is after decode.",
             1, "revision-1", "owner", "now"),
        )
        before_proof = json.loads(_related_evidence_context(db, "owner", "workspace", "target"))
        self.assertEqual(before_proof[0]["observation"], "The boundary check is after decode.")
        self.assertNotIn("flag", before_proof[0])
        db.execute(
            """INSERT INTO solver_jobs
               (id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                model,reasoning_effort,status,flag,released_ingested,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("d" * 32, "owner", "workspace", "source", "account", "codex",
             "gpt-6-sol", "high", "completed", "CTF{accepted}", 1, 1, 1),
        )
        shared = json.loads(_related_evidence_context(db, "owner", "workspace", "target"))
        self.assertEqual(shared[0]["flag"], "CTF{accepted}")
        self.assertEqual(shared[0]["flag_provenance"], "agent_accepted")
        self.assertNotIn("private description", str(shared))
        self.assertNotIn("private source notes", str(shared))
        self.assertEqual(_related_evidence_context(db, "other", "workspace", "target"), "")

        db.execute("UPDATE solver_jobs SET flag_rejected_at=2 WHERE challenge_id='source'")
        rejected = json.loads(_related_evidence_context(db, "owner", "workspace", "target"))
        self.assertNotIn("flag", rejected[0])
        db.execute("UPDATE solver_jobs SET flag_rejected_at=NULL WHERE challenge_id='source'")
        db.execute("UPDATE challenge_evidence_shares SET include_flag=0 WHERE source_challenge_id='source'")
        unselected = json.loads(_related_evidence_context(db, "owner", "workspace", "target"))
        self.assertNotIn("flag", unselected[0])
        db.execute("UPDATE challenge_evidence_shares SET include_flag=1 WHERE source_challenge_id='source'")
        db.execute("UPDATE challenges SET completion_source='manual' WHERE id='source'")
        manual = json.loads(_related_evidence_context(db, "owner", "workspace", "target"))
        self.assertNotIn("flag", manual[0])
        db.execute("UPDATE challenges SET completion_source='agent' WHERE id='source'")
        db.execute(
            "UPDATE challenge_evidence_shares SET observation=? WHERE source_challenge_id='source'",
            ("Credential sk-proj-abcdefghijklmnopqrstuvwxyz0123456789 was pasted.",),
        )
        redacted = _related_evidence_context(db, "owner", "workspace", "target")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123456789", redacted)
        self.assertIn("[redacted credential]", redacted)

        db.execute("UPDATE challenges SET updated_at='revision-2' WHERE id='source'")
        self.assertEqual(_related_evidence_context(db, "owner", "workspace", "target"), "")
        db.execute("UPDATE challenges SET updated_at='revision-1',status='running' WHERE id='source'")
        self.assertEqual(_related_evidence_context(db, "owner", "workspace", "target"), "")
        db.execute("UPDATE challenges SET status='solved' WHERE id='source'")
        db.execute("DELETE FROM challenge_relations")
        self.assertEqual(_related_evidence_context(db, "owner", "workspace", "target"), "")


if __name__ == "__main__":
    unittest.main()
