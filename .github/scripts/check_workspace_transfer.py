"""Offline workspace bundle round-trip and malformed-input regression checks."""

from __future__ import annotations

import json
import gc
import sys
import tempfile
import unittest
import uuid
import warnings
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.db import Settings, connect, initialize  # noqa: E402
from ctf_agent.storage_layout import StorageLayout  # noqa: E402
from ctf_agent.workspace_transfer import (  # noqa: E402
    TransferError, export_workspace, import_workspace,
    export_challenge, import_challenge, preview_bundle, lookup_import,
)
from ctf_agent.transfer_uploads import TransferUploadManager  # noqa: E402
from ctf_agent import workspace_transfer  # noqa: E402


class WorkspaceTransferTests(unittest.TestCase):
    def tearDown(self):
        # Existing schema initialization uses sqlite3's transaction context,
        # which does not close its connection on Windows until GC runs.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            gc.collect()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ctf-transfer-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.settings = Settings(
            data_dir=root / "data", db_dir=root / "db", config_dir=root / "config",
            log_dir=root / "logs", storage_min_free_bytes=0,
        )
        initialize(self.settings)

        def database():
            from contextlib import contextmanager

            @contextmanager
            def context():
                db = connect(self.settings)
                try:
                    with db:
                        yield db
                finally:
                    db.close()
            return context()

        self.layout = StorageLayout(self.settings, database)
        with closing(connect(self.settings)) as db, db:
            self.owner = db.execute(
                "SELECT value FROM meta WHERE key='legacy_owner_id'"
            ).fetchone()[0]
            self.workspace_id = uuid.uuid4().hex
            self.first = uuid.uuid4().hex
            self.second = uuid.uuid4().hex
            self.attachment = uuid.uuid4().hex
            stamp = "2026-11-01T00:00:00+00:00"
            db.execute(
                """INSERT INTO workspaces(id,name,description,flag_format,
                   open_challenge_after_create,created_at,updated_at,owner_user_id)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (self.workspace_id, "Test CTF", "Original", "FLAG{...}", 1,
                 stamp, stamp, self.owner),
            )
            db.execute(
                """INSERT INTO challenges(id,workspace_id,name,category,description,
                   status,notes,remote,remote_mode,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (self.first, self.workspace_id, "One", "web", "Read source",
                 "running", "Private notes", "https://secret.example/?token=value",
                 "endpoint", stamp, stamp),
            )
            db.execute(
                """INSERT INTO challenges(id,workspace_id,name,category,description,
                   status,completion_source,flag,notes,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (self.second, self.workspace_id, "Two", "crypto", "Decrypt",
                 "solved", "agent", "FLAG{example}",
                 "Solution notes\n\n# Write-up\nProof.", stamp, stamp),
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS challenge_writeups(
                   challenge_id TEXT PRIMARY KEY,markdown TEXT NOT NULL,
                   created_at TEXT NOT NULL,updated_at TEXT NOT NULL)"""
            )
            db.execute(
                "INSERT INTO challenge_writeups VALUES(?,?,?,?)",
                (self.second, "# Write-up\nProof.", stamp, stamp),
            )
            db.execute(
                "INSERT INTO challenge_relations VALUES(?,?,?,?)",
                (self.workspace_id, self.first, self.second, stamp),
            )
            columns = {row[1] for row in db.execute(
                "PRAGMA table_info(challenge_evidence_shares)"
            )}
            if "reapproval_required" not in columns:
                db.execute(
                    "ALTER TABLE challenge_evidence_shares ADD COLUMN "
                    "reapproval_required INTEGER NOT NULL DEFAULT 0"
                )
            db.execute(
                """INSERT INTO challenge_evidence_shares(
                   workspace_id,target_challenge_id,source_challenge_id,
                   observation,include_flag,source_updated_at,
                   verified_by_user_id,verified_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (self.workspace_id, self.first, self.second,
                 "Confirmed observation", 1, stamp, self.owner, stamp),
            )
            db.execute(
                """INSERT INTO challenge_evidence_shares(
                   workspace_id,target_challenge_id,source_challenge_id,
                   observation,include_flag,source_updated_at,
                   verified_by_user_id,verified_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (self.workspace_id, self.second, self.first,
                 "", 1, stamp, self.owner, stamp),
            )
            db.execute(
                "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
                (self.attachment, self.workspace_id, self.first,
                 "source.bin", self.attachment, 6, stamp),
            )
            db.execute("CREATE TABLE provider_accounts(id TEXT, secret TEXT)")
            db.execute("INSERT INTO provider_accounts VALUES(?,?)",
                       ("account", "DO_NOT_EXPORT_THIS_CREDENTIAL"))
        source = self.layout.legacy_attachment_path(
            self.workspace_id, self.first, self.attachment, create_parent=True
        )
        source.write_bytes(b"\x00\xffcode")
        self.archive = root / "workspace.zip"

    def export(self, **kwargs):
        return export_workspace(
            self.settings, self.layout, self.owner, self.workspace_id,
            self.archive, **kwargs,
        )

    def test_round_trip_remaps_ids_and_excludes_credentials(self):
        result = self.export()
        self.assertEqual(result["attachment_count"], 1)
        with zipfile.ZipFile(self.archive) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
            self.assertEqual(set(bundle.namelist()),
                             {"manifest.json", "solver-history.jsonl",
                              f"attachments/{self.attachment}"})
            self.assertEqual(manifest["challenges"][0]["remote"], "")
            self.assertEqual(manifest["challenges"][0]["remote_mode"], "unknown")
            self.assertNotIn("DO_NOT_EXPORT_THIS_CREDENTIAL", json.dumps(manifest))
            self.assertNotIn("owner_user_id", json.dumps(manifest))
            self.assertNotIn("ctfd_id", json.dumps(manifest))
            self.assertEqual(len(manifest["evidence_shares"]), 2)
        preview = preview_bundle(
            self.archive, settings=self.settings, owner_user_id=self.owner
        )
        self.assertEqual(preview["evidence_share_count"], 2)
        self.assertEqual(preview["flag_share_count"], 2)
        self.assertTrue(preview["flag_shares_require_reapproval"])
        self.assertEqual(preview["name_collisions"], ["Test CTF"])
        imported = import_workspace(self.settings, self.layout, self.owner, self.archive)
        self.assertNotEqual(imported["workspace_id"], self.workspace_id)
        self.assertNotEqual(imported["challenge_ids"][self.first], self.first)
        with closing(connect(self.settings)) as db, db:
            rows = db.execute(
                "SELECT * FROM challenges WHERE workspace_id=? ORDER BY name",
                (imported["workspace_id"],),
            ).fetchall()
            self.assertEqual([(r["name"], r["status"]) for r in rows],
                             [("One", "stopped"), ("Two", "solved")])
            self.assertEqual(rows[1]["flag"], "FLAG{example}")
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM challenge_relations WHERE workspace_id=?",
                (imported["workspace_id"],),
            ).fetchone()[0], 1)
            shares = db.execute(
                """SELECT include_flag,reapproval_required,observation,
                          source_updated_at,source_challenge_id
                   FROM challenge_evidence_shares WHERE workspace_id=?""",
                (imported["workspace_id"],),
            ).fetchall()
            self.assertEqual(len(shares), 1)
            self.assertEqual((shares[0]["include_flag"], shares[0]["reapproval_required"]),
                             (0, 1))
            self.assertEqual(shares[0]["source_challenge_id"],
                             imported["challenge_ids"][self.second])
            self.assertEqual(shares[0]["source_updated_at"],
                             db.execute("SELECT updated_at FROM challenges WHERE id=?",
                                        (imported["challenge_ids"][self.second],)).fetchone()[0])
            writeup = db.execute(
                "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                (imported["challenge_ids"][self.second],),
            ).fetchone()[0]
            self.assertEqual(writeup, "# Write-up\nProof.")
            attachment = db.execute(
                "SELECT stored_name FROM attachments WHERE workspace_id=?",
                (imported["workspace_id"],),
            ).fetchone()[0]
        self.assertEqual(self.layout.legacy_attachment_path(
            imported["workspace_id"], imported["challenge_ids"][self.first],
            attachment,
        ).read_bytes(), b"\x00\xffcode")

    def test_remote_opt_in(self):
        self.export(include_remote=True)
        with zipfile.ZipFile(self.archive) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
            challenge = next(item for item in manifest["challenges"]
                             if item["id"] == self.first)
            self.assertIn("token=value", challenge["remote"])

    def test_workspace_bundle_preserves_clone_lineage_without_live_peer_shares(self):
        with closing(connect(self.settings)) as db, db:
            for challenge_id in (self.first, self.second):
                db.execute(
                    """INSERT INTO challenge_clone_members
                       (workspace_id,challenge_id,family_id,created_at)
                       VALUES(?,?,?,?)""",
                    (self.workspace_id, challenge_id, self.first,
                     "2026-11-01T00:00:00+00:00"),
                )
        self.export()
        with zipfile.ZipFile(self.archive) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
        self.assertEqual(
            {item["challenge_id"] for item in manifest["clone_members"]},
            {self.first, self.second},
        )
        self.assertIn("peer_evidence_ledger", manifest["excluded"])
        imported = import_workspace(self.settings, self.layout, self.owner, self.archive)
        with closing(connect(self.settings)) as db:
            members = db.execute(
                """SELECT challenge_id,family_id FROM challenge_clone_members
                    WHERE workspace_id=?""", (imported["workspace_id"],),
            ).fetchall()
        self.assertEqual(len(members), 2)
        self.assertEqual(
            {row["challenge_id"] for row in members},
            set(imported["challenge_ids"].values()),
        )
        self.assertEqual(
            {row["family_id"] for row in members},
            {imported["challenge_ids"][self.first]},
        )

    def test_previous_bundle_version_remains_importable(self):
        self.export()
        legacy = self.archive.with_name("legacy-v2.zip")
        with zipfile.ZipFile(self.archive) as source, zipfile.ZipFile(legacy, "w") as target:
            for item in source.infolist():
                content = source.read(item.filename)
                if item.filename == "manifest.json":
                    manifest = json.loads(content)
                    manifest["version"] = 2
                    manifest.pop("clone_members")
                    content = json.dumps(manifest).encode("utf-8")
                target.writestr(item, content)
        imported = import_workspace(self.settings, self.layout, self.owner, legacy)
        self.assertEqual(imported["challenge_count"], 2)

    def test_single_challenge_bundle_imports_into_existing_workspace(self):
        result = export_challenge(
            self.settings, self.layout, self.owner, self.workspace_id,
            self.first, self.archive,
        )
        self.assertEqual(result["scope"], "challenge")
        with zipfile.ZipFile(self.archive) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
            self.assertEqual(manifest["scope"], "challenge")
            self.assertEqual([c["id"] for c in manifest["challenges"]], [self.first])
            self.assertEqual(manifest["relations"], [])
            self.assertEqual(manifest["clone_members"], [])
            self.assertEqual(manifest["evidence_shares"], [])
        imported = import_challenge(
            self.settings, self.layout, self.owner, self.workspace_id,
            self.archive,
        )
        self.assertNotEqual(imported["challenge_id"], self.first)
        with closing(connect(self.settings)) as db:
            challenge = db.execute(
                "SELECT status,remote FROM challenges WHERE id=?",
                (imported["challenge_id"],),
            ).fetchone()
            self.assertEqual((challenge["status"], challenge["remote"]),
                             ("stopped", ""))
            attachment = db.execute(
                "SELECT stored_name FROM attachments WHERE challenge_id=?",
                (imported["challenge_id"],),
            ).fetchone()[0]
        self.assertEqual(self.layout.legacy_attachment_path(
            self.workspace_id, imported["challenge_id"], attachment
        ).read_bytes(), b"\x00\xffcode")
        with self.assertRaisesRegex(TransferError, "existing workspace"):
            import_workspace(self.settings, self.layout, self.owner, self.archive)

    def test_wrong_owner_rejected_and_readable_edits_synced(self):
        with self.assertRaises(TransferError):
            export_workspace(self.settings, self.layout, "unknown", self.workspace_id,
                             self.archive)
        self.assertFalse(self.archive.exists())
        source = self.layout.legacy_attachment_path(
            self.workspace_id, self.first, self.attachment
        )
        source.write_bytes(b"bad")
        self.export()
        with zipfile.ZipFile(self.archive) as bundle:
            self.assertEqual(bundle.read(f"attachments/{self.attachment}"), b"bad")

    def test_corrupt_attachment_and_extra_path_are_rejected(self):
        self.export()
        with zipfile.ZipFile(self.archive) as source:
            manifest = source.read("manifest.json")
            history = source.read("solver-history.jsonl")
        invalid = self.archive.with_name("invalid.zip")
        with zipfile.ZipFile(invalid, "w") as target:
            target.writestr(f"attachments/{self.attachment}", b"BADBAD")
            target.writestr("solver-history.jsonl", history)
            target.writestr("manifest.json", manifest)
        with self.assertRaisesRegex(TransferError, "checksum"):
            import_workspace(self.settings, self.layout, self.owner, invalid)
        with closing(connect(self.settings)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0], 1)
        extra = self.archive.with_name("extra.zip")
        with zipfile.ZipFile(extra, "w") as target:
            target.writestr(f"attachments/{self.attachment}", b"\x00\xffcode")
            target.writestr("solver-history.jsonl", history)
            target.writestr("manifest.json", manifest)
            target.writestr("../outside", b"no")
        with self.assertRaisesRegex(TransferError, "unexpected"):
            import_workspace(self.settings, self.layout, self.owner, extra)

    def test_source_metadata_change_aborts_export(self):
        original = workspace_transfer._write_attachment

        def mutate_after_copy(*args):
            digest = original(*args)
            with closing(connect(self.settings)) as db, db:
                db.execute("UPDATE challenges SET notes='changed' WHERE id=?",
                           (self.first,))
            return digest

        with patch.object(workspace_transfer, "_write_attachment", mutate_after_copy):
            with self.assertRaisesRegex(TransferError, "changed during export"):
                self.export()
        self.assertFalse(self.archive.exists())

    def test_attachment_view_lookup_closes_scandir_on_early_return(self):
        self.export()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            with closing(connect(self.settings)) as db, db:
                name = self.layout.reserve_attachment(
                    db, self.workspace_id, self.first,
                    self.attachment, "source.bin",
                )
                self.assertEqual(name, "source.bin")
            gc.collect()
        self.assertFalse([
            item for item in caught
            if "scandir iterator" in str(item.message)
        ])

    def test_missing_or_inactive_import_owner_does_not_publish(self):
        self.export()
        with self.assertRaisesRegex(TransferError, "owner"):
            import_workspace(self.settings, self.layout, "missing", self.archive)
        with closing(connect(self.settings)) as db, db:
            db.execute("UPDATE users SET active=0 WHERE id=?", (self.owner,))
        with self.assertRaisesRegex(TransferError, "owner"):
            import_workspace(self.settings, self.layout, self.owner, self.archive)
        with closing(connect(self.settings)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0], 1)

    def test_workspace_import_commit_survives_crash_before_upload_consumed(self):
        self.export()
        manager = TransferUploadManager(self.settings)
        upload = manager.create(self.owner, self.archive.stat().st_size)
        upload_id = upload["upload_id"]
        manager.append(self.owner, upload_id, 0, self.archive.read_bytes())
        manager.finalize(self.owner, upload_id)
        # Simulate a process dying after the import commit but before the
        # outer upload manager has marked this session consumed.
        first = import_workspace(
            self.settings, self.layout, self.owner,
            manager.ready_path(self.owner, upload_id), source_upload_id=upload_id,
        )
        self.assertEqual(manager.status(self.owner, upload_id)["status"], "ready")
        self.assertEqual(
            lookup_import(self.settings, self.owner, upload_id, scope="workspace"),
            first,
        )
        second = import_workspace(
            self.settings, self.layout, self.owner,
            manager.ready_path(self.owner, upload_id), source_upload_id=upload_id,
        )
        self.assertEqual(first, second)
        with manager.import_slot(self.owner, upload_id) as path:
            self.assertEqual(import_workspace(
                self.settings, self.layout, self.owner, path,
                source_upload_id=upload_id,
            ), first)
        self.assertEqual(manager.status(self.owner, upload_id)["status"], "consumed")
        self.assertEqual(lookup_import(self.settings, self.owner, upload_id), first)
        with closing(connect(self.settings)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0], 2)

    def test_challenge_import_journal_prevents_duplicate_and_wrong_target(self):
        export_challenge(self.settings, self.layout, self.owner,
                         self.workspace_id, self.first, self.archive)
        upload_id = uuid.uuid4().hex
        first = import_challenge(
            self.settings, self.layout, self.owner, self.workspace_id,
            self.archive, source_upload_id=upload_id,
        )
        self.assertEqual(import_challenge(
            self.settings, self.layout, self.owner, self.workspace_id,
            self.archive, source_upload_id=upload_id,
        ), first)
        self.assertEqual(lookup_import(
            self.settings, self.owner, upload_id, scope="challenge",
            destination_workspace_id=self.workspace_id,
        ), first)
        with self.assertRaisesRegex(TransferError, "different scope"):
            lookup_import(self.settings, self.owner, upload_id, scope="workspace")
        with self.assertRaisesRegex(TransferError, "another workspace"):
            lookup_import(self.settings, self.owner, upload_id, scope="challenge",
                          destination_workspace_id=uuid.uuid4().hex)
        with closing(connect(self.settings)) as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM challenges WHERE workspace_id=?",
                (self.workspace_id,),
            ).fetchone()[0], 3)


if __name__ == "__main__":
    unittest.main()
