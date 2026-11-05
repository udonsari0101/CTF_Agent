"""Owner-scoped linked-evidence API and stale-share regressions."""

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


class RelatedEvidenceApiTest(unittest.TestCase):
    def test_explicit_share_staleness_and_unlink(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            app = create_app(Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="nologin",
            ))
            with TestClient(app) as browser:
                csrf = browser.get("/api/auth/state").json()["csrf_token"]
                browser.headers.update({"x-csrf-token": csrf})
                workspace = browser.post("/api/workspaces", json={"name": "Linked"}).json()["id"]
                other_workspace = browser.post("/api/workspaces", json={"name": "Other"}).json()["id"]

                def create(where, name):
                    response = browser.post(
                        f"/api/workspaces/{where}/challenges", json={"name": name}
                    )
                    self.assertEqual(response.status_code, 201, response.text)
                    return response.json()["id"]

                target = create(workspace, "Target")
                source = create(workspace, "Source")
                unrelated = create(other_workspace, "Unrelated")
                with app.state.connect() as db:
                    db.execute(
                        """UPDATE challenges SET status='solved',completion_source='manual',
                           flag='FLAG{manual}' WHERE id=?""", (source,)
                    )
                base = f"/api/workspaces/{workspace}/challenges/{target}/relations"
                linked = browser.post(base, json={"related_id": source})
                self.assertEqual(linked.status_code, 201, linked.text)
                self.assertIsNone(linked.json()["related_challenges"][0]["evidence_verified_at"])

                endpoint = base + f"/{source}/evidence"
                no_content = browser.put(endpoint, json={"observation": "", "include_flag": False})
                self.assertEqual(no_content.status_code, 422)
                manual_flag = browser.put(endpoint, json={"observation": "checked", "include_flag": True})
                self.assertEqual(manual_flag.status_code, 409)
                cross = browser.put(
                    base + f"/{unrelated}/evidence", json={"observation": "cross"}
                )
                self.assertEqual(cross.status_code, 404)
                shared = browser.put(endpoint, json={"observation": "Boundary verified locally."})
                self.assertEqual(shared.status_code, 200, shared.text)
                related = shared.json()["related_challenges"][0]
                self.assertEqual(related["evidence_observation"], "Boundary verified locally.")
                self.assertEqual(related["evidence_active"], 1)
                self.assertEqual(related["evidence_can_share_flag"], 0)
                with app.state.connect() as db:
                    db.execute(
                        "UPDATE challenges SET updated_at='after-source-change' WHERE id=?", (source,)
                    )
                stale = browser.get(f"/api/workspaces/{workspace}/challenges/{target}")
                self.assertEqual(stale.status_code, 200, stale.text)
                self.assertEqual(stale.json()["related_challenges"][0]["evidence_stale"], 1)
                renewed = browser.put(endpoint, json={"observation": "Rechecked."})
                self.assertEqual(renewed.status_code, 200, renewed.text)
                self.assertEqual(renewed.json()["related_challenges"][0]["evidence_active"], 1)
                removed = browser.delete(base + f"/{source}")
                self.assertEqual(removed.status_code, 200, removed.text)
                with app.state.connect() as db:
                    self.assertEqual(db.execute(
                        "SELECT COUNT(*) FROM challenge_evidence_shares WHERE workspace_id=?",
                        (workspace,),
                    ).fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
