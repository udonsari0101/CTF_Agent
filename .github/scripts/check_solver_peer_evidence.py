"""Clone lineage and explicitly opted-in live peer evidence regressions."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from local_test_client import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings
from ctf_agent.main import create_app


class SolverPeerEvidenceTest(unittest.TestCase):
    def test_clone_families_are_independent_until_explicit_share(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            app = create_app(Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="nologin",
            ))
            with TestClient(app) as browser:
                browser.headers.update({
                    "x-csrf-token": browser.get("/api/auth/state").json()["csrf_token"]
                })
                workspace = browser.post("/api/workspaces", json={"name": "Parallel"}).json()["id"]
                other_workspace = browser.post("/api/workspaces", json={"name": "Other"}).json()["id"]

                def create(where, name):
                    response = browser.post(
                        f"/api/workspaces/{where}/challenges", json={"name": name}
                    )
                    self.assertEqual(response.status_code, 201, response.text)
                    return response.json()["id"]

                original = create(workspace, "One problem")
                clone_a = browser.post(
                    f"/api/workspaces/{workspace}/challenges/{original}/clone"
                )
                self.assertEqual(clone_a.status_code, 201, clone_a.text)
                clone_a_id = clone_a.json()["id"]
                clone_b = browser.post(
                    f"/api/workspaces/{workspace}/challenges/{clone_a_id}/clone"
                )
                self.assertEqual(clone_b.status_code, 201, clone_b.text)
                clone_b_id = clone_b.json()["id"]
                unrelated = create(other_workspace, "Unrelated")
                jobs = {
                    original: "a" * 32,
                    clone_a_id: "b" * 32,
                    clone_b_id: "c" * 32,
                    unrelated: "d" * 32,
                }
                with app.state.connect() as db:
                    owner = db.execute(
                        "SELECT owner_user_id FROM workspaces WHERE id=?", (workspace,)
                    ).fetchone()[0]
                    groups = db.execute(
                        "SELECT challenge_id,family_id FROM challenge_clone_members WHERE workspace_id=?",
                        (workspace,),
                    ).fetchall()
                    self.assertEqual(len(groups), 3)
                    self.assertEqual({row["family_id"] for row in groups}, {original})
                    for number, (challenge_id, job_id) in enumerate(jobs.items(), 1):
                        where = other_workspace if challenge_id == unrelated else workspace
                        db.execute(
                            """INSERT INTO solver_jobs
                               (id,owner_user_id,workspace_id,challenge_id,account_id,
                                provider,model,reasoning_effort,status,created_at,updated_at)
                               VALUES(?,?,?,?,?,'codex','gpt-test','xhigh','running',?,?)""",
                            (job_id, owner, where, challenge_id, "e" * 32,
                             float(number), float(number)),
                        )
                    db.commit()

                target = jobs[clone_a_id]
                base = f"/api/solver/jobs/{target}"
                peers = browser.get(base + "/peers")
                self.assertEqual(peers.status_code, 200, peers.text)
                self.assertEqual(peers.json()["family_id"], original)
                self.assertEqual(
                    {item["job_id"] for item in peers.json()["peers"]},
                    {jobs[original], jobs[clone_b_id]},
                )
                self.assertEqual(peers.json()["shares"], [])
                observation = "Source inspection confirmed a 32-byte header."
                shared = browser.post(base + "/peer-evidence", json={
                    "source_job_id": jobs[original], "observation": observation,
                    "requested_delivery": "same_turn",
                })
                self.assertEqual(shared.status_code, 202, shared.text)
                self.assertEqual(shared.json()["delivery_status"], "queued")
                listed = browser.get(base + "/peers").json()["shares"]
                self.assertEqual(len(listed), 1)
                self.assertEqual(listed[0]["observation"], observation)
                with app.state.connect() as db:
                    guidance = db.execute(
                        "SELECT message FROM solver_job_guidance WHERE id=?",
                        (shared.json()["guidance_id"],),
                    ).fetchone()[0]
                    self.assertIn(observation, guidance)
                    self.assertIn(jobs[original], guidance)
                # A third sibling's new solve receives no unsolicited context.
                self.assertEqual(
                    browser.get(f"/api/solver/jobs/{jobs[clone_b_id]}/peers")
                    .json()["shares"], [],
                )
                for invalid_source in (target, jobs[unrelated]):
                    response = browser.post(base + "/peer-evidence", json={
                        "source_job_id": invalid_source, "observation": "Fact",
                    })
                    self.assertIn(response.status_code, (400, 404, 409))
                too_long = browser.post(base + "/peer-evidence", json={
                    "source_job_id": jobs[original], "observation": "x" * 1201,
                })
                self.assertEqual(too_long.status_code, 422)
                with app.state.connect() as db:
                    db.execute("UPDATE solver_jobs SET provider='claude' WHERE id=?", (target,))
                    db.commit()
                masked = browser.post(base + "/peer-evidence", json={
                    "source_job_id": jobs[original],
                    "observation": "Confirmed token sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
                })
                self.assertEqual(masked.status_code, 202, masked.text)
                self.assertEqual(masked.json()["requested_delivery"], "next_turn")
                self.assertIn("[redacted credential]", masked.json()["observation"])
                self.assertNotIn("sk-proj-", str(masked.json()))
                with app.state.connect() as db:
                    db.execute("UPDATE solver_jobs SET status='completed' WHERE id=?", (target,))
                    db.commit()
                stopped = browser.post(base + "/peer-evidence", json={
                    "source_job_id": jobs[original], "observation": "Too late",
                })
                self.assertEqual(stopped.status_code, 409)


if __name__ == "__main__":
    unittest.main()
