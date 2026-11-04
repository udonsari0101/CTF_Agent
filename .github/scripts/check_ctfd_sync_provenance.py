"""Offline CTFd refresh provenance and local-override regressions."""

import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2] if ".github" in Path(__file__).parts else Path.cwd()
sys.path.insert(0, str(ROOT))

from ctf_agent.ctfd import CTFdClient, CTFdError, ImportJobs, JOB_SCHEMA
from ctf_agent.db import Settings
from ctf_agent.main import create_app


SOURCE = "https://ctf.example"
CHALLENGE = "challenge-1"
WORKSPACE = "workspace-1"


def remote(name="Original", category="web", description="old text", endpoint="nc old:1", remote_id=7):
    return {
        "id": remote_id, "name": name, "category": category,
        "description": description, "remote": endpoint,
    }


class CTFdHiddenListingTest(unittest.TestCase):
    def test_hidden_listing_is_not_offered_for_new_sync(self):
        client = CTFdClient(SOURCE)
        client.authenticate = lambda: None
        requested = []

        def response(url):
            requested.append(url)
            if url.endswith("/api/v1/challenges"):
                return [
                    {"id": 7, "name": "Visible", "type": "standard"},
                    {"id": 8, "name": "Hidden", "type": "hidden"},
                ]
            if url.endswith("/api/v1/challenges/7"):
                return {"id": 7, "name": "Visible", "type": "standard", "files": []}
            self.fail("Hidden challenge detail must not be requested")

        client._json = response
        metadata = client.preview(metadata_only=True)
        self.assertEqual([item["id"] for item in metadata["challenges"]], [7])
        self.assertEqual(len(requested), 1)
        full = client.preview()
        self.assertEqual([item["id"] for item in full["challenges"]], [7])
        self.assertNotIn(SOURCE + "/api/v1/challenges/8", requested)

        explicit = client.preview([8], metadata_only=True)
        self.assertEqual(explicit["challenges"], [])
        self.assertEqual(explicit["errors"], [{
            "challenge_id": 8,
            "message": "The challenge is locked or hidden on the source site.",
        }])


class CTFdSyncProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE users(id TEXT PRIMARY KEY, active INTEGER);
            CREATE TABLE workspaces(id TEXT PRIMARY KEY, owner_user_id TEXT REFERENCES users(id));
            CREATE TABLE challenges(
                id TEXT PRIMARY KEY, workspace_id TEXT REFERENCES workspaces(id),
                name TEXT, category TEXT, description TEXT, remote TEXT,
                remote_mode TEXT, ctfd_id INTEGER, ctfd_url TEXT, updated_at TEXT);
            CREATE TABLE attachments(
                id TEXT PRIMARY KEY, workspace_id TEXT, challenge_id TEXT,
                original_name TEXT, stored_name TEXT, size INTEGER, created_at TEXT);
        """)
        self.db.executescript(JOB_SCHEMA)
        self.db.execute("INSERT INTO users VALUES('owner',1)")
        self.db.execute("INSERT INTO workspaces VALUES(?, 'owner')", (WORKSPACE,))
        self.db.execute(
            "INSERT INTO challenges VALUES(?,?,?,?,?,?,?,?,?,?)",
            (CHALLENGE, WORKSPACE, "Original", "web", "old text",
             "nc old:1", "endpoint", 7, SOURCE, "before"),
        )

    def tearDown(self):
        self.db.close()

    def merge(self, item, *, refresh=True, source=SOURCE):
        connection = item["remote"]
        ImportJobs.merge_remote_fields(
            self.db, WORKSPACE, CHALLENGE, source, item,
            connection, "endpoint" if connection else "none",
            refresh_metadata=refresh,
        )

    def challenge(self):
        return self.db.execute("SELECT * FROM challenges WHERE id=?", (CHALLENGE,)).fetchone()

    def test_unedited_fields_follow_upstream_but_local_overrides_survive(self):
        self.merge(remote())  # The first matching import establishes provenance.
        self.db.execute(
            "UPDATE challenges SET name='My label',description='my notes',remote='nc mine:9' WHERE id=?",
            (CHALLENGE,),
        )
        self.merge(remote("New name", "crypto", "new text", "nc new:2"))
        row = self.challenge()
        self.assertEqual((row["name"], row["category"], row["description"], row["remote"]),
                         ("My label", "crypto", "my notes", "nc mine:9"))
        provenance = self.db.execute(
            "SELECT * FROM ctfd_imported_fields WHERE challenge_id=?", (CHALLENGE,)
        ).fetchone()
        self.assertEqual((provenance["source_url"], provenance["remote_id"]), (SOURCE, 7))
        self.assertEqual((provenance["name"], provenance["category"], provenance["remote"]),
                         ("New name", "crypto", "nc new:2"))
        self.merge(remote("Newest", "misc", "later", "nc latest:3"))
        row = self.challenge()
        self.assertEqual((row["name"], row["category"], row["remote"]),
                         ("My label", "misc", "nc mine:9"))

    def test_endpoint_mode_is_preserved_with_a_local_override(self):
        self.merge(remote())
        self.db.execute("UPDATE challenges SET remote_mode='none',remote='' WHERE id=?", (CHALLENGE,))
        self.merge(remote(endpoint="nc new:2"), refresh=False)
        row = self.challenge()
        self.assertEqual((row["remote"], row["remote_mode"]), ("", "none"))

    def test_repeat_import_updates_only_unedited_endpoint(self):
        self.merge(remote())
        self.merge(remote("Changed upstream", "crypto", "changed", "nc new:2"), refresh=False)
        row = self.challenge()
        self.assertEqual((row["name"], row["category"], row["description"], row["remote"]),
                         ("Original", "web", "old text", "nc new:2"))
        self.merge(remote("Changed upstream", "crypto", "changed", "nc new:2"))
        self.assertEqual((self.challenge()["name"], self.challenge()["category"]),
                         ("Changed upstream", "crypto"))

    def test_refresh_selection_skips_unselected_fields_without_losing_baseline(self):
        self.merge(remote())
        update = remote("Changed", "crypto", "new description", "nc new:2")
        self.assertEqual(
            [item["field"] for item in ImportJobs.refresh_field_diff(
                self.db, WORKSPACE, CHALLENGE, SOURCE, update
            ) if item["selectable"]],
            ["name", "category", "description", "remote"],
        )
        ImportJobs.merge_remote_fields(
            self.db, WORKSPACE, CHALLENGE, SOURCE, update,
            update["remote"], "endpoint", refresh_metadata=True,
            selected_fields=["name"],
        )
        row = self.challenge()
        self.assertEqual(
            (row["name"], row["category"], row["description"], row["remote"]),
            ("Changed", "web", "old text", "nc old:1"),
        )
        later = ImportJobs.refresh_field_diff(
            self.db, WORKSPACE, CHALLENGE, SOURCE, update
        )
        self.assertEqual(
            [item["field"] for item in later if item["selectable"]],
            ["category", "description", "remote"],
        )

    def test_refresh_selection_never_overwrites_local_changes(self):
        self.merge(remote())
        self.db.execute(
            "UPDATE challenges SET name='Local name' WHERE id=?", (CHALLENGE,)
        )
        update = remote("Changed", "crypto", "new description", "nc new:2")
        diff = ImportJobs.refresh_field_diff(
            self.db, WORKSPACE, CHALLENGE, SOURCE, update
        )
        self.assertTrue(next(item for item in diff if item["field"] == "name")["local_override"])
        ImportJobs.merge_remote_fields(
            self.db, WORKSPACE, CHALLENGE, SOURCE, update,
            update["remote"], "endpoint", refresh_metadata=True,
            selected_fields=["name", "category"],
        )
        self.assertEqual((self.challenge()["name"], self.challenge()["category"]),
                         ("Local name", "crypto"))

    def test_legacy_challenge_preserves_fields_before_first_trusted_baseline(self):
        self.merge(remote("Upstream changed", "crypto", "updated", "nc new:2"))
        row = self.challenge()
        self.assertEqual((row["name"], row["category"], row["description"], row["remote"]),
                         ("Original", "web", "old text", "nc old:1"))
        # Once the operator aligns a field with upstream, future updates follow.
        self.db.execute("UPDATE challenges SET category='crypto' WHERE id=?", (CHALLENGE,))
        self.merge(remote("Later", "misc", "later", "nc later:3"))
        self.assertEqual(self.challenge()["category"], "misc")

    def test_wrong_origin_or_id_never_mutates_local_metadata(self):
        before = dict(self.challenge())
        for item, source in ((remote(remote_id=8), SOURCE),
                             (remote(), "https://elsewhere.example")):
            with self.assertRaises(CTFdError):
                self.merge(item, source=source)
        self.assertEqual(dict(self.challenge()), before)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM ctfd_imported_fields").fetchone()[0], 0)

    def test_same_name_different_remote_ids_have_separate_provenance(self):
        second = "challenge-2"
        self.db.execute(
            "INSERT INTO challenges VALUES(?,?,?,?,?,?,?,?,?,?)",
            (second, WORKSPACE, "Original", "web", "old text",
             "nc old:1", "endpoint", 8, SOURCE, "before"),
        )
        self.merge(remote())
        ImportJobs.merge_remote_fields(
            self.db, WORKSPACE, second, SOURCE, remote(remote_id=8),
            "nc old:1", "endpoint", refresh_metadata=True,
        )
        self.merge(remote(name="Only first changed", endpoint="nc first:2"))
        first = self.db.execute("SELECT name,remote FROM challenges WHERE id=?", (CHALLENGE,)).fetchone()
        other = self.db.execute("SELECT name,remote FROM challenges WHERE id=?", (second,)).fetchone()
        self.assertEqual(tuple(first), ("Only first changed", "nc first:2"))
        self.assertEqual(tuple(other), ("Original", "nc old:1"))
        identities = self.db.execute(
            "SELECT remote_id FROM ctfd_imported_fields ORDER BY remote_id"
        ).fetchall()
        self.assertEqual([row[0] for row in identities], [7, 8])

    def test_manual_attachment_and_solve_state_survive_metadata_refresh(self):
        self.db.execute("ALTER TABLE challenges ADD COLUMN status TEXT DEFAULT 'solved'")
        self.db.execute("ALTER TABLE challenges ADD COLUMN flag TEXT DEFAULT 'FLAG{local}'")
        self.db.execute("ALTER TABLE challenges ADD COLUMN notes TEXT DEFAULT 'manual analysis'")
        self.db.execute(
            "INSERT INTO attachments VALUES('manual',?,?, 'sample.bin','manual',42,'now')",
            (WORKSPACE, CHALLENGE),
        )
        self.merge(remote())
        self.merge(remote("Updated", "crypto", "updated", "nc new:2"))
        row = self.challenge()
        self.assertEqual((row["status"], row["flag"], row["notes"]),
                         ("solved", "FLAG{local}", "manual analysis"))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attachments WHERE id='manual'").fetchone()[0], 1)

    def test_refresh_publication_keeps_manual_attachment_flag_and_notes(self):
        self.db.execute("ALTER TABLE challenges ADD COLUMN status TEXT DEFAULT 'solved'")
        self.db.execute("ALTER TABLE challenges ADD COLUMN flag TEXT DEFAULT 'FLAG{local}'")
        self.db.execute("ALTER TABLE challenges ADD COLUMN notes TEXT DEFAULT 'manual analysis'")
        self.db.execute(
            "INSERT INTO attachments VALUES('manual',?,?, 'sample.bin','manual',42,'now')",
            (WORKSPACE, CHALLENGE),
        )
        self.merge(remote())
        self.db.execute("UPDATE challenges SET description='edited locally' WHERE id=?", (CHALLENGE,))
        self.db.commit()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db_path = root / "refresh.sqlite3"
            disk = sqlite3.connect(db_path)
            self.db.backup(disk)
            disk.execute(
                "CREATE TABLE readable_storage_paths(kind TEXT, entity_id TEXT, name TEXT)"
            )
            disk.execute(
                """INSERT INTO ctfd_jobs
                   (id,owner_user_id,workspace_id,source_url,auth_type,mode,
                    target_challenge_id,status,created_at,updated_at)
                   VALUES('job','owner',?,?, 'token','refresh',?,'running','now','now')""",
                (WORKSPACE, SOURCE, CHALLENGE),
            )
            disk.commit()
            disk.close()

            def connect():
                result = sqlite3.connect(db_path)
                result.row_factory = sqlite3.Row
                result.execute("PRAGMA foreign_keys=ON")
                return result

            noop = lambda *args, **kwargs: None
            worker = object.__new__(ImportJobs)
            worker.app = SimpleNamespace(state=SimpleNamespace(connect=connect))
            worker._storage_layout = SimpleNamespace(
                plan_refresh_views=noop, plan_delete=noop,
                reconcile_refresh_views=noop, finish_deletions=noop,
            )
            worker.path = lambda *parts: root.joinpath(*parts)
            worker._remove_job_staging = lambda *_: True
            update = remote("Updated", "crypto", "upstream changed", "nc new:2")
            update["files"] = []
            worker.publish_refresh(
                "job", WORKSPACE, "owner", SOURCE, update, CHALLENGE,
                threading.Event(),
            )
            with closing(connect()) as read:
                row = read.execute("SELECT * FROM challenges WHERE id=?", (CHALLENGE,)).fetchone()
                self.assertEqual((row["name"], row["category"], row["description"]),
                                 ("Updated", "crypto", "edited locally"))
                self.assertEqual((row["status"], row["flag"], row["notes"]),
                                 ("solved", "FLAG{local}", "manual analysis"))
                files = read.execute("SELECT id FROM attachments WHERE challenge_id=?", (CHALLENGE,)).fetchall()
                self.assertEqual([item[0] for item in files], ["manual"])
                self.assertEqual(read.execute("SELECT refreshed FROM ctfd_jobs WHERE id='job'").fetchone()[0], 1)


class CTFdRefreshPreviewContract(unittest.TestCase):
    def test_new_sync_reports_unavailable_source_rows_without_changing_local_data(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            settings = Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="nologin",
            )
            app = create_app(settings)

            class Client:
                def __init__(self, **kwargs):
                    self.url = kwargs["url"]
                    self.auth_type = kwargs["auth_type"]
                    self.cancel_event = None

                def submission_readiness(self):
                    return True, ""

                def clear_credentials(self):
                    pass

                def preview(self, selected=None, *, metadata_only=False, exclude_ids=None):
                    self.test_case.assertEqual(set(exclude_ids or ()), {7, 8, 9})
                    self.test_case.assertTrue(metadata_only)
                    return {
                        "source_url": self.url, "challenges": [], "errors": [],
                        "details_pending": True,
                        "_listing_states": {7: "visible", 8: "hidden"},
                    }

            Client.test_case = self
            app.state.ctfd_client_factory = Client
            with TestClient(app) as browser:
                csrf = browser.get("/api/auth/state").json()["csrf_token"]
                browser.headers.update({"x-csrf-token": csrf})
                workspace = browser.post("/api/workspaces", json={"name": "Sync"}).json()["id"]
                challenge_ids = []
                for remote_id in (7, 8, 9):
                    challenge_id = browser.post(
                        f"/api/workspaces/{workspace}/challenges",
                        json={"name": f"Local {remote_id}"},
                    ).json()["id"]
                    challenge_ids.append(challenge_id)
                    with app.state.connect() as db:
                        db.execute(
                            """UPDATE challenges SET ctfd_id=?,ctfd_url=?,notes=?,flag=?
                               WHERE id=?""",
                            (remote_id, SOURCE, "local notes", "FLAG{local}", challenge_id),
                        )
                saved = browser.put(
                    f"/api/workspaces/{workspace}/ctfd/connection",
                    json={"url": SOURCE, "auth_type": "token", "token": "saved-token"},
                )
                self.assertEqual(saved.status_code, 200, saved.text)
                response = browser.post(f"/api/workspaces/{workspace}/ctfd/sync/preview", json={})
                self.assertEqual(response.status_code, 200, response.text)
                data = response.json()
                self.assertEqual(data["new_count"], 0)
                self.assertEqual(data["existing_count"], 3)
                self.assertEqual(
                    {item["remote_id"]: item["state"] for item in data["source_statuses"]},
                    {7: "visible", 8: "hidden", 9: "unlisted"},
                )
                self.assertEqual(
                    {item["remote_id"]: item["name"] for item in data["source_statuses"]},
                    {7: "Local 7", 8: "Local 8", 9: "Local 9"},
                )
                self.assertNotIn("_listing_states", data)
                with app.state.connect() as db:
                    rows = db.execute(
                        "SELECT notes,flag FROM challenges WHERE workspace_id=?", (workspace,)
                    ).fetchall()
                self.assertEqual([tuple(row) for row in rows],
                                 [("local notes", "FLAG{local}")] * 3)

    def test_saved_and_one_off_preview_do_not_replace_saved_connection(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            settings = Settings(
                root / "data", root / "db", root / "config", root / "logs",
                storage_min_free_bytes=0, auth_mode="nologin",
            )
            app = create_app(settings)
            created = []

            class Client:
                def __init__(self, **kwargs):
                    self.url = kwargs["url"]
                    self.auth_type = kwargs["auth_type"]
                    self.token = kwargs.get("token", "")
                    self.cancel_event = None
                    created.append(self)

                def submission_readiness(self):
                    return True, ""

                def clear_credentials(self):
                    self.token = ""

                def preview(self, selected=None, *, metadata_only=False, exclude_ids=None):
                    self.seen_token = self.token
                    self.seen_selection = selected
                    return {
                        "source_url": self.url,
                        "challenges": [{
                            "id": 7, "name": "Updated", "category": "web",
                            "description": "new text", "remote": "nc new:2",
                            "files": [],
                        }],
                        "errors": [],
                    }

            app.state.ctfd_client_factory = Client
            with TestClient(app) as browser:
                csrf = browser.get("/api/auth/state").json()["csrf_token"]
                browser.headers.update({"x-csrf-token": csrf})
                workspace = browser.post("/api/workspaces", json={"name": "Preview"}).json()["id"]
                challenge = browser.post(
                    f"/api/workspaces/{workspace}/challenges",
                    json={"name": "Original"},
                ).json()["id"]
                with app.state.connect() as db:
                    db.execute(
                        "UPDATE challenges SET ctfd_id=7,ctfd_url=?,category='web',description='old text',remote='nc old:1',remote_mode='endpoint' WHERE id=?",
                        (SOURCE, challenge),
                    )
                    db.execute(
                        """INSERT INTO ctfd_imported_fields
                           (challenge_id,workspace_id,source_url,remote_id,name,category,description,remote,remote_mode)
                           VALUES(?,?,?,7,'Original','web','old text','nc old:1','endpoint')""",
                        (challenge, workspace, SOURCE),
                    )
                base = f"/api/workspaces/{workspace}/ctfd"
                saved = browser.put(
                    base + "/connection",
                    json={"url": SOURCE, "auth_type": "token", "token": "saved-token"},
                )
                self.assertEqual(saved.status_code, 200, saved.text)
                with app.state.connect() as db:
                    before = tuple(db.execute(
                        "SELECT generation,credentials_ciphertext FROM ctfd_submit_connections WHERE workspace_id=?",
                        (workspace,),
                    ).fetchone())
                endpoint = f"/api/workspaces/{workspace}/challenges/{challenge}/ctfd/refresh/preview"
                saved_preview = browser.post(endpoint, json={})
                self.assertEqual(saved_preview.status_code, 200, saved_preview.text)
                self.assertEqual(created[-1].seen_token, "saved-token")
                self.assertEqual(created[-1].seen_selection, [7])
                self.assertTrue(any(item["field"] == "name" and item["selectable"]
                                    for item in saved_preview.json()["field_diff"]))
                manual = browser.post(
                    endpoint,
                    json={"url": SOURCE, "auth_type": "token", "token": "one-off-token"},
                )
                self.assertEqual(manual.status_code, 200, manual.text)
                self.assertEqual(created[-1].seen_token, "one-off-token")
                with app.state.connect() as db:
                    after = tuple(db.execute(
                        "SELECT generation,credentials_ciphertext FROM ctfd_submit_connections WHERE workspace_id=?",
                        (workspace,),
                    ).fetchone())
                self.assertEqual(after, before)
                self.assertNotIn("saved-token", saved_preview.text)
                self.assertNotIn("one-off-token", manual.text)
                applied = browser.post(
                    f"/api/workspaces/{workspace}/challenges/{challenge}/ctfd/refresh",
                    json={
                        "preview_id": saved_preview.json()["preview_id"],
                        "selected_fields": ["name"],
                    },
                )
                self.assertEqual(applied.status_code, 202, applied.text)
                job_id = applied.json()["job"]["id"]
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    state = browser.get(base + "/jobs/" + job_id).json()["job"]
                    if state["status"] not in {"queued", "running"}:
                        break
                    time.sleep(.02)
                self.assertEqual(state["status"], "completed", state)
                with app.state.connect() as db:
                    row = db.execute(
                        "SELECT name,description,remote FROM challenges WHERE id=?", (challenge,)
                    ).fetchone()
                    stored_fields = db.execute(
                        "SELECT selected_fields FROM ctfd_jobs WHERE id=?", (job_id,)
                    ).fetchone()[0]
                self.assertEqual(tuple(row), ("Updated", "old text", "nc old:1"))
                self.assertEqual(stored_fields, '["name"]')


if __name__ == "__main__":
    unittest.main()
