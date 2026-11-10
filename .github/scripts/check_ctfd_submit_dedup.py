"""Offline checks for at-most-once CTFd submission and provenance."""

from __future__ import annotations

import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from local_test_client import TestClient

from ctf_agent.ctfd import CTFdClient, CTFdError
from ctf_agent.db import Settings
from ctf_agent.main import create_app

SITE = "https://ctfd.example.test"
FLAG = "test{offline_dedup_only}"


class SubmissionReadinessTests(unittest.TestCase):
    def test_token_readiness_does_not_depend_on_challenge_listing(self):
        client = CTFdClient(SITE, auth_type="token", token="offline-token")
        with patch.object(client, "validate") as validate, patch.object(client, "_json") as listing:
            self.assertEqual(client.submission_readiness(), (True, ""))
            validate.assert_called_once_with()
            listing.assert_not_called()
        with patch.object(client, "validate", side_effect=CTFdError("The remote request timed out.")):
            with self.assertRaises(CTFdError):
                client.submission_readiness()

    def test_transient_password_csrf_page_failure_is_not_auth_failure(self):
        client = CTFdClient(
            SITE, auth_type="password", username="offline", password="offline-password"
        )
        with patch.object(client, "validate"), patch.object(
            client, "_json", return_value=[]
        ), patch.object(client, "_get") as page:
            for message in (
                "The remote request timed out.",
                "The remote server returned HTTP 503.",
                "The remote server returned HTTP 520.",
                "The CTFd site rate limited this request.",
            ):
                with self.subTest(message=message):
                    page.side_effect = CTFdError(message)
                    with self.assertRaises(CTFdError):
                        client.submission_readiness()

            page.side_effect = CTFdError("CTFd denied access.")
            self.assertEqual(client.submission_readiness(), (False, "csrf_unavailable"))
            page.side_effect = None
            page.return_value = b'<script>{"csrfNonce":"1234567890abcdef"}</script>'
            self.assertEqual(client.submission_readiness(), (True, ""))


class FakeRemote:
    def __init__(self):
        self.submit_calls = 0
        self.submit_mode = "correct"
        self.solved = False
        self.attempt_limit = False
        self.history = None
        self.readiness = True

    def submission_readiness(self):
        return self.readiness, "ready" if self.readiness else "csrf_unavailable"

    def challenge_submission_state(self, _challenge_id):
        return {"solved_by_me": self.solved, "attempt_limit_reached": self.attempt_limit}

    def submit(self, challenge_id, flag):
        assert challenge_id == 17 and flag == FLAG
        self.submit_calls += 1
        if self.submit_mode == "response_lost":
            raise CTFdError("remote request failed")
        if self.submit_mode == "unexpected_error":
            raise RuntimeError("synthetic transport failure")
        return {"status": self.submit_mode}

    def challenge_solved_by_me(self, _challenge_id):
        return self.solved

    def submission_status_for_flag(self, _challenge_id, flag):
        assert flag == FLAG
        return self.history

    def clear_credentials(self):
        pass


class AtMostOnceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.app = create_app(Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        ))
        self.remote = FakeRemote()
        self.app.state.ctfd_client_factory = lambda **_kwargs: self.remote
        self.http = TestClient(self.app)
        self.addCleanup(self.http.close)
        csrf = self.http.get("/api/auth/state").json()["csrf_token"]
        self.http.headers.update({"x-csrf-token": csrf})
        response = self.http.post("/api/workspaces", json={"name": "offline"})
        self.assertEqual(response.status_code, 201, response.text)
        self.workspace_id = response.json()["id"]
        response = self.http.post(
            f"/api/workspaces/{self.workspace_id}/challenges",
            json={"name": "offline", "category": "web", "description": "test",
                  "remote_mode": "none", "flag": FLAG},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.challenge_id = response.json()["id"]
        self.service = self.app.state.ctfd_submit
        with self.service.db() as db:
            self.owner_id = db.execute(
                "SELECT owner_user_id FROM workspaces WHERE id=?", (self.workspace_id,)
            ).fetchone()[0]
            db.execute(
                "UPDATE challenges SET ctfd_id=17,ctfd_url=?,flag=?,status='flag_found',"
                "completion_source='agent' WHERE id=?",
                (SITE, FLAG, self.challenge_id),
            )
        base = f"/api/workspaces/{self.workspace_id}/ctfd"
        response = self.http.put(base + "/connection", json={
            "url": SITE, "auth_type": "token", "token": "offline-token",
        })
        self.assertEqual(response.status_code, 200, response.text)
        response = self.http.put(base + "/settings", json={"auto_submit": True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(self.service.enqueue_flag(
            self.owner_id, self.workspace_id, self.challenge_id, FLAG,
        ))

    def job(self):
        with self.service.db() as db:
            return dict(db.execute(
                "SELECT status,result_code,attempts,dispatch_started,source_solver_job_id "
                "FROM ctfd_submit_jobs WHERE challenge_id=?", (self.challenge_id,),
            ).fetchone())

    def test_incorrect_agent_flag_cancels_writeup_and_rejects_after_release(self):
        source_id = uuid.uuid4().hex
        coordinator = self.app.state.solver_jobs
        with self.service.db() as db:
            db.execute(
                """INSERT INTO solver_jobs
                   (id,owner_user_id,workspace_id,challenge_id,account_id,
                    provider,model,reasoning_effort,status,flag,created_at,updated_at)
                   VALUES(?,?,?,?,?,'codex','test-model','medium','writing',?,?,?)""",
                (source_id, self.owner_id, self.workspace_id, self.challenge_id,
                 uuid.uuid4().hex, FLAG, 1.0, 1.0),
            )
            db.execute(
                "UPDATE ctfd_submit_jobs SET source_solver_job_id=? WHERE challenge_id=?",
                (source_id, self.challenge_id),
            )
        self.remote.submit_mode = "incorrect"
        with patch.object(coordinator, "cancel") as cancel, patch.object(
            coordinator, "reject_candidate"
        ) as reject:
            self.assertTrue(self.service.process_once())
            cancel.assert_called_once_with(source_id, self.owner_id)
            reject.assert_not_called()
            with self.service.db() as db:
                db.execute(
                    "UPDATE solver_jobs SET released_ingested=1,status='completed',released_at=2 "
                    "WHERE id=?", (source_id,),
                )
            self.assertTrue(self.service.process_once())
            reject.assert_called_once_with(source_id, self.owner_id)
        with self.service.db() as db:
            state = db.execute(
                "SELECT solver_rejection_state FROM ctfd_submit_jobs WHERE challenge_id=?",
                (self.challenge_id,),
            ).fetchone()[0]
        self.assertEqual(state, "applied")
        self.assertEqual(self.remote.submit_calls, 1)

    def test_operator_can_reject_active_candidate_before_writeup(self):
        source_id = uuid.uuid4().hex
        with self.service.db() as db:
            db.execute(
                """INSERT INTO solver_jobs
                   (id,owner_user_id,workspace_id,challenge_id,account_id,
                    provider,model,reasoning_effort,status,flag,created_at,updated_at)
                   VALUES(?,?,?,?,?,'codex','test-model','medium','writing',?,?,?)""",
                (source_id, self.owner_id, self.workspace_id, self.challenge_id,
                 uuid.uuid4().hex, FLAG, 1.0, 1.0),
            )
        response = self.http.post(f"/api/solver/jobs/{source_id}/reject-flag")
        self.assertEqual(response.status_code, 200, response.text)
        with self.service.db() as db:
            job = db.execute(
                "SELECT flag_rejected_at,cancel_requested FROM solver_jobs WHERE id=?",
                (source_id,),
            ).fetchone()
            challenge = db.execute(
                "SELECT flag,status FROM challenges WHERE id=?", (self.challenge_id,)
            ).fetchone()
            checkpoint = db.execute(
                "SELECT source_job_id FROM solver_retry_checkpoints WHERE challenge_id=?",
                (self.challenge_id,),
            ).fetchone()
        self.assertIsNotNone(job["flag_rejected_at"])
        self.assertEqual(job["cancel_requested"], 1)
        self.assertIsNone(challenge["flag"])
        self.assertEqual(challenge["status"], "pending")
        self.assertEqual(checkpoint["source_job_id"], source_id)
        coordinator = self.app.state.solver_jobs
        job_ref = {"id": source_id, "workspace_id": self.workspace_id,
                   "challenge_id": self.challenge_id}
        for sequence, kind, extra in (
            (1, "flag", {"flag": FLAG}),
            (2, "writeup", {"flag": FLAG, "writeup_markdown": "# wrong candidate"}),
            (3, "released", {"status": "completed", "flag": FLAG}),
        ):
            coordinator._commit_event(job_ref, {
                "protocol": 1, "job_id": source_id, "sequence": sequence,
                "kind": kind, "created_at": float(sequence), **extra,
            })
        with self.service.db() as db:
            challenge = db.execute(
                "SELECT flag,status FROM challenges WHERE id=?", (self.challenge_id,)
            ).fetchone()
            stored = db.execute(
                "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                (self.challenge_id,),
            ).fetchone()
            job = db.execute(
                "SELECT status FROM solver_jobs WHERE id=?", (source_id,)
            ).fetchone()
        self.assertIsNone(challenge["flag"])
        self.assertEqual(challenge["status"], "pending")
        self.assertIsNone(stored)
        self.assertEqual(job["status"], "cancelled")

    def test_lost_response_never_reposts_even_when_remote_unsolved(self):
        self.remote.submit_mode = "response_lost"
        self.assertTrue(self.service.process_once())
        self.assertEqual(self.job()["result_code"], "outcome_unknown")
        self.assertEqual(self.remote.submit_calls, 1)
        self.assertTrue(self.service.process_once())
        self.assertEqual(self.job()["result_code"], "remote_unsolved")
        self.assertFalse(self.service.process_once())
        self.assertEqual(self.remote.submit_calls, 1)

    def test_lost_response_can_reconcile_solved_status(self):
        self.remote.submit_mode = "response_lost"
        self.service.process_once()
        self.remote.solved = True
        self.service.process_once()
        self.assertEqual(self.job()["result_code"], "remote_solved")
        self.assertEqual(self.remote.submit_calls, 1)

    def test_exact_flag_history_records_remote_result_without_repost(self):
        self.remote.submit_mode = "response_lost"
        self.service.process_once()
        self.remote.history = "correct"
        self.service.process_once()
        self.assertEqual(self.job()["result_code"], "remote_submission_correct")
        self.assertEqual(self.remote.submit_calls, 1)

    def test_failed_reconciliation_stays_terminal(self):
        self.remote.submit_mode = "unexpected_error"
        self.service.process_once()
        self.remote.challenge_solved_by_me = lambda _id: (_ for _ in ()).throw(
            RuntimeError("synthetic read failure")
        )
        self.service.process_once()
        self.assertEqual(self.job()["result_code"], "remote_check_unavailable")
        self.assertEqual(self.remote.submit_calls, 1)

    def test_remote_attempt_limit_prevents_post(self):
        self.remote.attempt_limit = True
        self.service.process_once()
        self.assertEqual(self.job()["result_code"], "attempt_limit")
        self.assertEqual(self.remote.submit_calls, 0)

    def test_remote_solved_prevents_post(self):
        self.remote.solved = True
        self.service.process_once()
        self.assertEqual(self.job()["result_code"], "already_solved")
        self.assertEqual(self.remote.submit_calls, 0)

    def test_definitive_response_is_stored_once(self):
        self.service.process_once()
        self.assertEqual(self.job()["result_code"], "accepted")
        self.assertEqual(self.remote.submit_calls, 1)
        self.assertFalse(self.service.process_once())

    def test_preflight_failure_can_retry_before_dispatch(self):
        self.remote.submission_readiness = lambda: (_ for _ in ()).throw(
            CTFdError("remote request failed")
        )
        self.service.process_once()
        self.assertEqual(self.job()["status"], "retry")
        self.assertEqual(self.job()["dispatch_started"], 0)
        self.assertEqual(self.remote.submit_calls, 0)

    def test_preflight_http_520_can_retry_without_dispatch(self):
        self.remote.submission_readiness = lambda: (_ for _ in ()).throw(
            CTFdError("The remote server returned HTTP 520.")
        )
        self.service.process_once()
        self.assertEqual(self.job()["status"], "retry")
        self.assertEqual(self.job()["dispatch_started"], 0)
        self.assertEqual(self.remote.submit_calls, 0)

    def test_preflight_rate_limit_can_retry_without_dispatch(self):
        self.remote.submission_readiness = lambda: (_ for _ in ()).throw(
            CTFdError("The CTFd site rate limited this request.")
        )
        self.service.process_once()
        self.assertEqual(self.job()["status"], "retry")
        self.assertEqual(self.job()["result_code"], "rate_limited")
        self.assertEqual(self.job()["dispatch_started"], 0)
        self.assertEqual(self.remote.submit_calls, 0)

    def test_legacy_running_dispatch_is_not_retried(self):
        with self.service.db() as db:
            db.execute(
                "UPDATE ctfd_submit_jobs SET status='running',attempts=1,dispatch_started=1 "
                "WHERE challenge_id=?", (self.challenge_id,),
            )
        self.service.process_once()
        self.assertEqual(self.remote.submit_calls, 0)
        self.assertNotEqual(self.job()["status"], "retry")

    def test_submission_keeps_matching_solver_job_provenance(self):
        with self.service.db() as db:
            db.execute("DELETE FROM ctfd_submit_jobs WHERE challenge_id=?", (self.challenge_id,))
            db.execute(
                """INSERT INTO solver_jobs
                   (id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                    model,reasoning_effort,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,'codex','test-model','low','completed',0,0)""",
                ("source-job", self.owner_id, self.workspace_id, self.challenge_id, "account"),
            )
        self.assertTrue(self.service.enqueue_flag(
            self.owner_id, self.workspace_id, self.challenge_id, FLAG, "agent", "source-job",
        ))
        self.assertEqual(self.job()["source_solver_job_id"], "source-job")
        history = self.http.get(f"/api/workspaces/{self.workspace_id}/ctfd/submissions")
        self.assertEqual(history.status_code, 200, history.text)
        self.assertEqual(history.json()["submissions"][0]["source_solver_job_id"], "source-job")

    def test_submission_drops_unrelated_solver_job_provenance(self):
        with self.service.db() as db:
            db.execute("DELETE FROM ctfd_submit_jobs WHERE challenge_id=?", (self.challenge_id,))
        self.assertTrue(self.service.enqueue_flag(
            self.owner_id, self.workspace_id, self.challenge_id, FLAG, "agent", "other-job",
        ))
        self.assertIsNone(self.job()["source_solver_job_id"])

    def test_solver_flag_hook_passes_source_job_to_submitter(self):
        submitted = []
        self.app.state.telegram_flag_found = lambda *_args: True
        self.app.state.ctfd_auto_submit_flag = lambda *args: submitted.append(args) or True
        self.assertTrue(self.app.state.solver._flag_committed(
            self.owner_id, self.workspace_id, self.challenge_id, FLAG, "source-job",
        ))
        self.assertEqual(submitted, [(
            self.owner_id, self.workspace_id, self.challenge_id, FLAG, "agent", "source-job",
        )])


if __name__ == "__main__":
    unittest.main(verbosity=2)
