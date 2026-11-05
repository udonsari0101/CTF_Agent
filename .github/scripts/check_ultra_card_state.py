"""Offline API and browser regression for Ultra versus remote input cards."""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from local_test_client import TestClient


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings  # noqa: E402
from ctf_agent.main import create_app  # noqa: E402
from ctf_agent.solver_retry import RetryCheckpoint, encode_checkpoint  # noqa: E402


class UltraCardStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        settings = Settings(
            root / "data", root / "db", root / "config", root / "logs",
            storage_min_free_bytes=0, auth_mode="nologin",
        )
        self.app = create_app(settings)
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)
        csrf = self.client.get("/api/auth/state").json()["csrf_token"]
        self.client.headers.update({"x-csrf-token": csrf})
        response = self.client.post("/api/workspaces", json={"name": "card test"})
        self.assertEqual(response.status_code, 201, response.text)
        self.workspace_id = response.json()["id"]
        response = self.client.post(
            f"/api/workspaces/{self.workspace_id}/challenges",
            json={"name": "sample", "description": "offline sample", "remote_mode": "none"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.challenge_id = response.json()["id"]
        self.coordinator = self.app.state.solver_jobs.primary
        self.job_id = uuid.uuid4().hex
        with self.coordinator._connect() as db:
            self.owner_id = db.execute(
                "SELECT owner_user_id FROM workspaces WHERE id=?", (self.workspace_id,)
            ).fetchone()[0]
            db.execute(
                """INSERT INTO solver_jobs(
                   id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                   model,reasoning_effort,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,'codex','offline-test','high','needs_input',100,100)""",
                (self.job_id, self.owner_id, self.workspace_id,
                 self.challenge_id, uuid.uuid4().hex),
            )

    def arm_ultra(self) -> None:
        checkpoint = encode_checkpoint(RetryCheckpoint(
            revision=1, rejected_flags=(), private_notes="", prior_writeup="",
            reason="ultra_escalation",
        ))
        with self.coordinator._connect() as db:
            db.execute(
                """UPDATE solver_jobs
                      SET ultra_escalation_mode='auto',released_ingested=1,error_json=?
                    WHERE id=?""",
                (json.dumps({"code": "ultra_escalation_requested"}), self.job_id),
            )
            db.execute(
                """INSERT INTO solver_retry_checkpoints
                   (challenge_id,workspace_id,owner_user_id,checkpoint_json,
                    source_job_id,created_at,updated_at)
                   VALUES(?,?,?,?,?,100,100)""",
                (self.challenge_id, self.workspace_id, self.owner_id,
                 checkpoint, self.job_id),
            )

    def summary(self, error: object, status: str = "needs_input") -> dict:
        with self.coordinator._connect() as db:
            db.execute(
                "UPDATE solver_jobs SET status=?,error_json=? WHERE id=?",
                (status, json.dumps(error), self.job_id),
            )
        response = self.client.get(f"/api/workspaces/{self.workspace_id}/challenges")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["challenges"][0]["latest_solver"]

    def test_safe_input_classification(self) -> None:
        sensitive = "do-not-expose-provider-error-text"
        ultra = self.summary({"code": "ultra_escalation_requested", "message": sensitive})
        self.assertEqual(ultra["input_request_kind"], "ultra_escalation")
        self.assertFalse(ultra["input_ready_to_retry"])
        self.assertNotIn(sensitive, json.dumps(ultra))

        remote = self.summary({"code": "remote_input_required", "message": sensitive})
        self.assertEqual(remote["input_request_kind"], "remote_input")
        self.assertNotIn(sensitive, json.dumps(remote))

        other = self.summary({"code": "unexpected", "message": sensitive})
        self.assertEqual(other["input_request_kind"], "other")
        completed = self.summary({"code": "ultra_escalation_requested"}, status="completed")
        self.assertIsNone(completed["input_request_kind"])

    def test_replaced_checkpoint_removes_approval_and_auto_pending(self) -> None:
        self.arm_ultra()
        initial = self.coordinator.get(self.job_id, self.owner_id)["ultra_escalation"]
        self.assertTrue(initial["eligible"])
        self.assertTrue(initial["auto_pending"])
        with self.coordinator._connect() as db:
            db.execute(
                "UPDATE solver_retry_checkpoints SET source_job_id=? WHERE challenge_id=?",
                (uuid.uuid4().hex, self.challenge_id),
            )
        stale = self.coordinator.get(self.job_id, self.owner_id)["ultra_escalation"]
        self.assertFalse(stale["eligible"])
        self.assertFalse(stale["auto_pending"])
        self.assertEqual(self.coordinator.claim_auto_ultra_requests(), [])
        with self.coordinator._connect() as db:
            attempted = db.execute(
                "SELECT ultra_auto_attempted FROM solver_jobs WHERE id=?", (self.job_id,)
            ).fetchone()[0]
        self.assertEqual(attempted, 0)

    def test_newer_solve_supersedes_approval_even_before_checkpoint_replacement(self) -> None:
        self.arm_ultra()
        with self.coordinator._connect() as db:
            db.execute(
                """INSERT INTO solver_jobs(
                   id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                   model,reasoning_effort,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,'codex','offline-test','high','queued',101,101)""",
                (uuid.uuid4().hex, self.owner_id, self.workspace_id,
                 self.challenge_id, uuid.uuid4().hex),
            )
        stale = self.coordinator.get(self.job_id, self.owner_id)["ultra_escalation"]
        self.assertFalse(stale["eligible"])
        self.assertFalse(stale["auto_pending"])
        self.assertEqual(self.coordinator.claim_auto_ultra_requests(), [])

    def test_concurrent_auto_claim_is_once_only_with_manual_fallback(self) -> None:
        self.arm_ultra()
        with ThreadPoolExecutor(max_workers=4) as executor:
            claims = list(executor.map(self.coordinator.claim_auto_ultra_requests, (1,) * 4))
        self.assertEqual(sum(len(items) for items in claims), 1)
        self.assertEqual([item for items in claims for item in items],
                         [(self.job_id, self.owner_id)])
        self.assertEqual(self.coordinator.claim_auto_ultra_requests(), [])
        state = self.coordinator.get(self.job_id, self.owner_id)["ultra_escalation"]
        self.assertTrue(state["eligible"])
        self.assertFalse(state["auto_pending"])

    def test_child_uniqueness_prevents_duplicate_escalation(self) -> None:
        self.arm_ultra()
        with self.coordinator._connect() as db:
            first = uuid.uuid4().hex
            child_values = (first, self.owner_id, self.workspace_id,
                            self.challenge_id, uuid.uuid4().hex, self.job_id)
            db.execute(
                """INSERT INTO solver_jobs(
                   id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                   model,reasoning_effort,status,ultra_source_job_id,created_at,updated_at)
                   VALUES(?,?,?,?,?,'codex','offline-test','ultra','failed',?,101,101)""",
                child_values,
            )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.coordinator._connect() as db:
                db.execute(
                    """INSERT INTO solver_jobs(
                       id,owner_user_id,workspace_id,challenge_id,account_id,provider,
                       model,reasoning_effort,status,ultra_source_job_id,created_at,updated_at)
                       VALUES(?,?,?,?,?,'codex','offline-test','ultra','failed',?,102,102)""",
                    (uuid.uuid4().hex, self.owner_id, self.workspace_id,
                     self.challenge_id, uuid.uuid4().hex, self.job_id),
                )
        self.assertEqual(self.coordinator.claim_auto_ultra_requests(), [])
        state = self.coordinator.get(self.job_id, self.owner_id)["ultra_escalation"]
        self.assertEqual(state["started_job_id"], first)
        self.assertFalse(state["eligible"])
        self.assertFalse(state["auto_pending"])

    def test_card_routes_ultra_to_detail_without_remote_form(self) -> None:
        browser = next((path for name in ("google-chrome", "chromium", "chrome", "msedge")
                        if (path := shutil.which(name))), None)
        if not browser:
            browser = next((str(path) for path in (
                Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            ) if path.exists()), None)
        if not browser:
            self.skipTest("Chrome/Chromium is unavailable")

        source = (ROOT / "ctf_agent/web/app.js").read_text(encoding="utf-8")
        start = source.index("function challengeRunSummary(challenge)")
        end = source.index("function challengeListParams()", start)
        implementation = source[start:end]
        css = "\n".join((ROOT / f"ctf_agent/web/{name}").read_text(encoding="utf-8")
                        for name in ("style.css", "theme.css"))
        self.assertNotIn("</style", css.lower())
        fixture = """<!doctype html><html><head><meta charset="utf-8"><style>""" + css + """</style></head><body><pre id="result">PENDING</pre><script>
const i18n={locale:'ko',t:value=>value};
const statuses={stopped:'중단'},solverPhases={needs_input:'추가 입력 필요'};
const solverTerminalPhases=new Set(['needs_input']);
const startingListSolvers=new Set();
const esc=value=>String(value??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
const date=()=>'';
""" + implementation + """
const base={id:'challenge-1',name:'sample',category:'web',description:'',status:'stopped',
  flag:'',completion_source:null,has_writeup:false,updated_at:1,remote_mode:'none',
  latest_solver:{status:'needs_input',configuration:{provider:'codex',model:'test',reasoning_effort:'high'}}};
function render(kind){
  const challenge=structuredClone(base);challenge.latest_solver.input_request_kind=kind;
  const node=document.createElement('div');node.innerHTML=challengeCardMarkup(challenge,'workspace-1');
  return node;
}
const ultra=render('ultra_escalation'),remote=render('remote_input'),other=render('other');
const checks={
  ultraLabel:ultra.textContent.includes('Ultra 전환 제안'),
  ultraDetail:!!ultra.querySelector('.challenge-inline-attention [data-action="open-challenge"]'),
  ultraNoRemote:!ultra.querySelector('form.challenge-inline-input'),
  remoteForm:!!remote.querySelector('form.challenge-inline-input input[name="remote"]'),
  remoteLabel:remote.textContent.includes('원격 정보 요청'),
  unknownNoRemote:!other.querySelector('form.challenge-inline-input'),
  unknownDetail:!!other.querySelector('.challenge-inline-attention [data-action="open-challenge"]')
};
const narrow=document.createElement('div');narrow.style.width='260px';
const longRemote=structuredClone(base);longRemote.latest_solver.input_request_kind='remote_input';
longRemote.remote='nc '+'a'.repeat(240)+' 31337';
narrow.innerHTML=challengeCardMarkup(longRemote,'workspace-1');document.body.append(narrow);
const composer=narrow.querySelector('form.challenge-inline-input');
checks.composerFits=!!composer&&composer.scrollWidth<=composer.clientWidth+1&&narrow.scrollWidth<=narrow.clientWidth+1;
document.querySelector('#result').textContent=Object.values(checks).every(Boolean)?'PASS':'FAIL '+JSON.stringify(checks);
</script></body></html>"""
        page = Path(self.temp.name) / "card.html"
        page.write_text(fixture, encoding="utf-8")
        command = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
                   "--disable-extensions", f"--user-data-dir={Path(self.temp.name) / 'profile'}",
                   "--virtual-time-budget=1000", "--dump-dom", page.as_uri()]
        if sys.platform != "win32":
            command.append("--no-sandbox")
        result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                encoding="utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, result.stderr[-1000:])
        self.assertIn('<pre id="result">PASS</pre>', result.stdout, result.stdout[-1500:])


if __name__ == "__main__":
    unittest.main()
