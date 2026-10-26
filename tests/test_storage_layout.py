from __future__ import annotations

import os
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest

from ctf_agent.db import Settings, connect, initialize
from ctf_agent.storage_layout import StorageLayout, readable_filename, readable_name
from ctf_agent.storage_layout import StorageArtifactError
from ctf_agent.writeups import WriteupStore


WORKSPACE = "1" * 32
CHALLENGE = "2" * 32
ATTACHMENT = "3" * 32


def environment(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data",
        db_dir=tmp_path / "database",
        config_dir=tmp_path / "config",
        log_dir=tmp_path / "logs",
        storage_min_free_bytes=0,
    )
    initialize(settings)

    @contextmanager
    def database():
        connection = connect(settings)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    WriteupStore(database)
    with database() as db:
        owner = db.execute(
            "SELECT value FROM meta WHERE key='legacy_owner_id'"
        ).fetchone()[0]
    return settings, database, owner


def insert_challenge(database, owner, *, workspace=WORKSPACE, challenge=CHALLENGE,
                     workspace_name="한글 CTF", challenge_name="Token Guard"):
    with database() as db:
        db.execute(
            """INSERT INTO workspaces
               (id,name,description,flag_format,created_at,updated_at,owner_user_id)
               VALUES(?,?, '',NULL,'2026-01-01','2026-01-01',?)""",
            (workspace, workspace_name, owner),
        )
        db.execute(
            """INSERT INTO challenges
               (id,workspace_id,name,category,description,created_at,updated_at)
               VALUES(?,?,?,'','','2026-01-01','2026-01-01')""",
            (challenge, workspace, challenge_name),
        )


def canonical(settings, workspace=WORKSPACE, challenge=CHALLENGE,
              stored=ATTACHMENT):
    return (
        settings.data_dir / "workspaces" / workspace / "challenges" /
        challenge / "attachments" / stored
    )


def test_migration_keeps_uuid_canonical_and_hard_links_large_attachment(tmp_path, monkeypatch):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    source = canonical(settings)
    source.parent.mkdir(parents=True)
    with source.open("wb") as output:
        output.truncate(128 * 1024 * 1024 + 17)
    with database() as db:
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (ATTACHMENT, WORKSPACE, CHALLENGE, "firmware image.bin", ATTACHMENT,
             source.stat().st_size, "2026-01-01"),
        )

    # A migration must never materialize attachment bytes in Python.
    monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(
        AssertionError(f"unexpected byte copy: {self}")
    ) if self == source else open(self, "rb").read())
    layout = StorageLayout(settings, database)
    with database() as db:
        view = layout.readable_attachment_path(
            WORKSPACE, CHALLENGE, ATTACHMENT, db=db
        )
        columns = {row[1] for row in db.execute("PRAGMA table_info(attachments)")}
        stored = db.execute(
            "SELECT stored_name FROM attachments WHERE id=?", (ATTACHMENT,)
        ).fetchone()[0]
    assert source.exists() and stored == ATTACHMENT
    assert "readable_name" not in columns and "storage_name" not in columns
    assert os.path.samefile(source, view)
    assert view.name == "firmware image.bin"
    assert view.stat().st_size == 128 * 1024 * 1024 + 17


def test_external_same_name_is_preserved_and_unicode_case_duplicates_are_numbered(tmp_path):
    settings, database, owner = environment(tmp_path)
    layout = StorageLayout(settings, database)
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        layout.reserve_workspace(db, WORKSPACE, "Ｆｌａｇ")
        db.execute(
            "INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) VALUES(?,?,'x','x',?)",
            (WORKSPACE, "Ｆｌａｇ", owner),
        )
        layout.reserve_challenge(db, WORKSPACE, CHALLENGE, "Challenge")
        db.execute(
            "INSERT INTO challenges(id,workspace_id,name,created_at,updated_at) VALUES(?,?,?,'x','x')",
            (CHALLENGE, WORKSPACE, "Challenge"),
        )
    challenge_path = layout.challenge_path(WORKSPACE, CHALLENGE, create=True)
    attachments = challenge_path / "attachments"
    attachments.mkdir(exist_ok=True)
    external = attachments / "ＦＬＡＧ.bin"
    external.write_bytes(b"external")
    source = canonical(settings)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"canonical")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (ATTACHMENT, WORKSPACE, CHALLENGE, "flag.BIN", ATTACHMENT, 9, "x"),
        )
        layout.ensure_attachment_view(
            db, WORKSPACE, CHALLENGE,
            db.execute("SELECT * FROM attachments WHERE id=?", (ATTACHMENT,)).fetchone(),
        )
        view = layout.readable_attachment_path(
            WORKSPACE, CHALLENGE, ATTACHMENT, db=db
        )
    assert external.read_bytes() == b"external"
    assert view.name.casefold() != external.name.casefold()
    assert "(2)" in view.name
    assert os.path.samefile(source, view)


def test_crash_tail_markers_and_existing_link_migrate_idempotently(tmp_path):
    settings, database, owner = environment(tmp_path)
    layout = StorageLayout(settings, database)
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        layout.reserve_workspace(db, WORKSPACE, "Stable")
        db.execute(
            "INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) VALUES(?,?,'x','x',?)",
            (WORKSPACE, "Stable", owner),
        )
        layout.reserve_challenge(db, WORKSPACE, CHALLENGE, "Stable problem")
        db.execute(
            "INSERT INTO challenges(id,workspace_id,name,created_at,updated_at) VALUES(?,?,?,'x','x')",
            (CHALLENGE, WORKSPACE, "Stable problem"),
        )
    workspace_path = layout.workspace_path(WORKSPACE, create=True)
    challenge_path = layout.challenge_path(WORKSPACE, CHALLENGE, create=True)
    source = canonical(settings)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"payload")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (ATTACHMENT, WORKSPACE, CHALLENGE, "payload.bin", ATTACHMENT, 7, "x"),
        )
        layout.reserve_attachment(db, WORKSPACE, CHALLENGE, ATTACHMENT, "payload.bin")
        row = db.execute("SELECT * FROM attachments WHERE id=?", (ATTACHMENT,)).fetchone()
        link = layout.ensure_attachment_view(db, WORKSPACE, CHALLENGE, row)
        db.execute("DELETE FROM readable_storage_paths")
        db.execute("DELETE FROM readable_text_state")

    layout.migrate()
    first = layout.readable_attachment_path(WORKSPACE, CHALLENGE, ATTACHMENT)
    layout.migrate()
    second = layout.readable_attachment_path(WORKSPACE, CHALLENGE, ATTACHMENT)
    assert workspace_path == layout.workspace_path(WORKSPACE)
    assert challenge_path == layout.challenge_path(WORKSPACE, CHALLENGE)
    assert first == second == link
    assert os.path.samefile(source, second)


@pytest.mark.parametrize("link_swapped", (False, True))
def test_refresh_crash_around_link_swap_reclaims_the_original_readable_name(
    tmp_path, link_swapped
):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    old_id = ATTACHMENT
    new_id = "4" * 32
    old_source = canonical(settings, stored=old_id)
    old_source.parent.mkdir(parents=True)
    old_source.write_bytes(b"old")
    with database() as db:
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (old_id, WORKSPACE, CHALLENGE, "payload.bin", old_id, 3, "x"),
        )
    layout = StorageLayout(settings, database)
    readable = layout.readable_attachment_path(WORKSPACE, CHALLENGE, old_id)

    new_source = canonical(settings, stored=new_id)
    new_source.write_bytes(b"new")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        layout.reserve_attachment(
            db, WORKSPACE, CHALLENGE, new_id, "payload.bin"
        )
        layout.plan_refresh_views(
            db,
            WORKSPACE,
            CHALLENGE,
            [{
                "attachment_id": old_id,
                "file_index": 0,
                "original_name": "payload.bin",
                "readable_name": readable.name,
            }],
            [{
                "id": new_id,
                "file_index": 0,
                "original_name": "payload.bin",
            }],
        )
        layout.plan_delete(
            db, "attachment", old_id, WORKSPACE,
            challenge_id=CHALLENGE, stored_name=old_id,
            readable_name=readable.name,
        )
        db.execute("DELETE FROM attachments WHERE id=?", (old_id,))
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (new_id, WORKSPACE, CHALLENGE, "payload.bin", new_id, 3, "x"),
        )

    # Model both process-death boundaries: immediately after the attachment DB
    # commit, and after os.replace(readable) but before the mapping transfer.
    if link_swapped:
        replacement = readable.with_name(".refresh-crash.link")
        os.link(new_source, replacement)
        os.replace(replacement, readable)

    recovered = StorageLayout(settings, database)
    assert recovered.readable_attachment_path(
        WORKSPACE, CHALLENGE, new_id
    ) == readable
    assert readable.read_bytes() == b"new"
    assert os.path.samefile(new_source, readable)
    assert not old_source.exists()
    with database() as db:
        rows = db.execute(
            """SELECT entity_id,name FROM readable_storage_paths
                 WHERE kind='attachment' AND parent_id=?""",
            (CHALLENGE,),
        ).fetchall()
    assert [(row["entity_id"], row["name"]) for row in rows] == [
        (new_id, "payload.bin")
    ]


def test_direct_attachment_and_markdown_edits_reconcile_without_loss(tmp_path):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    source = canonical(settings)
    source.parent.mkdir(parents=True)
    source.write_bytes(b"old bytes")
    with database() as db:
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (ATTACHMENT, WORKSPACE, CHALLENGE, "edit.bin", ATTACHMENT, 9, "x"),
        )
        db.execute(
            "INSERT INTO challenge_writeups VALUES(?,?,?,?)",
            (CHALLENGE, "# 기존 풀이", "2026-01-01", "2026-01-01"),
        )
    layout = StorageLayout(settings, database)
    view = layout.readable_attachment_path(WORKSPACE, CHALLENGE, ATTACHMENT)
    replacement = view.with_name("replacement.tmp")
    replacement.write_bytes(b"new external bytes")
    os.replace(replacement, view)
    challenge_path = layout.challenge_path(WORKSPACE, CHALLENGE)
    (challenge_path / "notes.md").write_text("사용자 풀이 노트", encoding="utf-8")
    writeup_replacement = challenge_path / "writeup.tmp"
    writeup_replacement.write_text("# 보완된 풀이\n\n```python\nprint('solve')\n```", encoding="utf-8")
    os.replace(writeup_replacement, challenge_path / "writeup.md")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        layout.sync_challenge(db, WORKSPACE, CHALLENGE)
    with database() as db:
        attachment = db.execute(
            "SELECT size FROM attachments WHERE id=?", (ATTACHMENT,)
        ).fetchone()
        notes = db.execute(
            "SELECT notes FROM challenges WHERE id=?", (CHALLENGE,)
        ).fetchone()[0]
        writeup = db.execute(
            "SELECT markdown FROM challenge_writeups WHERE challenge_id=?", (CHALLENGE,)
        ).fetchone()[0]
    recovery = source.parent.parent / ".readable-recovery"
    assert source.read_bytes() == b"new external bytes"
    assert attachment["size"] == len(b"new external bytes")
    assert any(path.read_bytes() == b"old bytes" for path in recovery.iterdir())
    assert "사용자 풀이 노트" in notes and "# 보완된 풀이" in notes
    assert writeup.startswith("# 보완된 풀이")


def test_external_notes_edit_during_solve_is_merged_with_committed_writeup(tmp_path):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    with database() as db:
        db.execute(
            "UPDATE challenges SET notes=? WHERE id=?",
            ("solver-start notes", CHALLENGE),
        )
    layout = StorageLayout(settings, database)
    notes_path = layout.challenge_path(WORKSPACE, CHALLENGE) / "notes.md"
    notes_path.write_text("host edit during solve", encoding="utf-8")
    markdown = "# Finished solution\n\n```python\nprint('flag')\n```"
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO challenge_writeups VALUES(?,?,?,?)",
            (CHALLENGE, markdown, "2026-01-01", "2026-01-01"),
        )
        db.execute(
            "UPDATE challenges SET notes=? WHERE id=?",
            ("solver-start notes", CHALLENGE),
        )
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        layout.sync_challenge(db, WORKSPACE, CHALLENGE)
    with database() as db:
        notes = db.execute(
            "SELECT notes FROM challenges WHERE id=?", (CHALLENGE,)
        ).fetchone()[0]
    assert "host edit during solve" in notes
    assert markdown in notes
    assert notes_path.read_text(encoding="utf-8") == notes


def test_names_are_stable_after_display_rename_and_concurrent_duplicates(tmp_path):
    settings, database, owner = environment(tmp_path)
    layout = StorageLayout(settings, database)

    def create(index):
        workspace_id = f"{index + 10:032x}"
        with database() as db:
            db.execute("BEGIN IMMEDIATE")
            name = layout.reserve_workspace(db, workspace_id, "Same")
            db.execute(
                "INSERT INTO workspaces(id,name,created_at,updated_at,owner_user_id) VALUES(?,?,'x','x',?)",
                (workspace_id, "Same", owner),
            )
        layout.workspace_path(workspace_id, create=True)
        return workspace_id, name

    with ThreadPoolExecutor(max_workers=2) as pool:
        created = list(pool.map(create, range(2)))
    assert {name for _identifier, name in created} == {"Same", "Same (2)"}
    first_id = created[0][0]
    before = layout.workspace_path(first_id)
    with database() as db:
        db.execute("UPDATE workspaces SET name='Renamed' WHERE id=?", (first_id,))
    layout.migrate()
    assert layout.workspace_path(first_id) == before


def test_traversal_reserved_names_and_symlinks_are_never_followed(tmp_path):
    assert readable_name("../../CON") == "_.._CON"
    assert readable_filename("..\\..\\secret.bin") == "_.._secret.bin"
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = settings.data_dir / "workspaces" / WORKSPACE
    workspace.mkdir(parents=True)
    try:
        os.symlink(outside, workspace / "challenges", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    layout = StorageLayout(settings, database)
    with pytest.raises(RuntimeError, match="directory"):
        layout.legacy_attachment_path(
            WORKSPACE, CHALLENGE, ATTACHMENT, create_parent=True
        )
    assert not any(outside.iterdir())


def test_unlinked_reservation_never_promotes_an_external_file_to_canonical(tmp_path):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    layout = StorageLayout(settings, database)
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (ATTACHMENT, WORKSPACE, CHALLENGE, "same.bin", ATTACHMENT, 8, "x"),
        )
        layout.reserve_attachment(
            db, WORKSPACE, CHALLENGE, ATTACHMENT, "same.bin"
        )
        first = layout.readable_attachment_path(
            WORKSPACE, CHALLENGE, ATTACHMENT, db=db
        )
    first.write_bytes(b"external")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM attachments WHERE id=?", (ATTACHMENT,)
        ).fetchone()
        allocated = layout.ensure_attachment_view(
            db, WORKSPACE, CHALLENGE, row, view_wins=False
        )
        mapping = db.execute(
            "SELECT name,linked FROM readable_storage_paths WHERE kind='attachment' AND entity_id=?",
            (ATTACHMENT,),
        ).fetchone()
    assert first.read_bytes() == b"external"
    assert allocated != first and "(2)" in allocated.name
    assert not canonical(settings).exists()
    assert tuple(mapping) == (allocated.name, 0)


@pytest.mark.parametrize("kind", ("attachment", "challenge", "workspace"))
def test_delete_commit_crash_is_finished_without_removing_unknown_files(
    tmp_path, kind
):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    source = canonical(settings)
    source.parent.mkdir(parents=True)
    source.write_bytes(b"managed")
    with database() as db:
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (ATTACHMENT, WORKSPACE, CHALLENGE, "managed.bin", ATTACHMENT, 7, "x"),
        )
    layout = StorageLayout(settings, database)
    challenge_view = layout.challenge_path(WORKSPACE, CHALLENGE)
    workspace_view = layout.workspace_path(WORKSPACE)
    preserved = (
        challenge_view / "keep-user-file.txt"
        if kind == "challenge"
        else workspace_view / "keep-user-file.txt"
    )
    if kind != "attachment":
        preserved.write_bytes(b"keep")

    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        if kind == "attachment":
            attachment = db.execute(
                "SELECT * FROM attachments WHERE id=?", (ATTACHMENT,)
            ).fetchone()
            layout.remove_attachment_view(
                db, WORKSPACE, CHALLENGE, attachment
            )
            layout.plan_delete(
                db, kind, ATTACHMENT, WORKSPACE,
                challenge_id=CHALLENGE, stored_name=ATTACHMENT,
            )
            layout.forget(db, kind, ATTACHMENT)
            db.execute("DELETE FROM attachments WHERE id=?", (ATTACHMENT,))
        elif kind == "challenge":
            layout.remove_challenge_view(db, WORKSPACE, CHALLENGE)
            layout.plan_delete(
                db, kind, CHALLENGE, WORKSPACE, challenge_id=CHALLENGE
            )
            layout.forget_challenge(db, CHALLENGE)
            db.execute("DELETE FROM challenges WHERE id=?", (CHALLENGE,))
        else:
            layout.remove_workspace_view(db, WORKSPACE)
            layout.plan_delete(db, kind, WORKSPACE, WORKSPACE)
            layout.forget_workspace(db, WORKSPACE)
            db.execute("DELETE FROM workspaces WHERE id=?", (WORKSPACE,))

    # No post-commit cleanup ran. Constructor recovery represents restart.
    StorageLayout(settings, database)
    with database() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM readable_delete_handoffs"
        ).fetchone()[0] == 0
    if kind == "attachment":
        assert not source.exists()
        assert not (challenge_view / "attachments" / "managed.bin").exists()
    elif kind == "challenge":
        assert not layout.legacy_challenge_path(WORKSPACE, CHALLENGE).exists()
        assert preserved.read_bytes() == b"keep"
        assert not (challenge_view / ".ctf-agent-id").exists()
    else:
        assert not layout.legacy_workspace_path(WORKSPACE).exists()
        assert preserved.read_bytes() == b"keep"
        assert not (workspace_view / ".ctf-agent-id").exists()


def test_attachment_delete_preserves_an_unreconciled_atomic_replacement(tmp_path):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    source = canonical(settings)
    source.parent.mkdir(parents=True)
    source.write_bytes(b"old canonical")
    with database() as db:
        db.execute(
            "INSERT INTO attachments VALUES(?,?,?,?,?,?,?)",
            (ATTACHMENT, WORKSPACE, CHALLENGE, "edit.bin", ATTACHMENT, 13, "x"),
        )
    layout = StorageLayout(settings, database)
    view = layout.readable_attachment_path(WORKSPACE, CHALLENGE, ATTACHMENT)
    replacement = view.with_name("replacement.tmp")
    replacement.write_bytes(b"unreconciled user bytes")
    os.replace(replacement, view)
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        attachment = db.execute(
            "SELECT * FROM attachments WHERE id=?", (ATTACHMENT,)
        ).fetchone()
        layout.remove_attachment_view(db, WORKSPACE, CHALLENGE, attachment)
        layout.plan_delete(
            db, "attachment", ATTACHMENT, WORKSPACE,
            challenge_id=CHALLENGE, stored_name=ATTACHMENT,
        )
        layout.forget(db, "attachment", ATTACHMENT)
        db.execute("DELETE FROM attachments WHERE id=?", (ATTACHMENT,))
    layout.finish_deletions()
    assert not source.exists()
    assert view.read_bytes() == b"unreconciled user bytes"


def test_finish_deletions_releases_sqlite_writer_before_tree_removal(
    tmp_path, monkeypatch
):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    layout = StorageLayout(settings, database)
    canonical_challenge = layout.legacy_challenge_path(
        WORKSPACE, CHALLENGE, create=True
    )
    (canonical_challenge / "large-tree-entry").write_bytes(b"x")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        layout.remove_challenge_view(db, WORKSPACE, CHALLENGE)
        layout.plan_delete(
            db, "challenge", CHALLENGE, WORKSPACE, challenge_id=CHALLENGE
        )
        layout.forget_challenge(db, CHALLENGE)
        db.execute("DELETE FROM challenges WHERE id=?", (CHALLENGE,))

    original_rmtree = shutil.rmtree
    write_succeeded = False

    def remove_while_another_user_writes(path):
        nonlocal write_succeeded
        with database() as db:
            db.execute("PRAGMA busy_timeout=1")
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('delete-lock-probe','ok')"
            )
        write_succeeded = True
        original_rmtree(path)

    monkeypatch.setattr(
        "ctf_agent.storage_layout.shutil.rmtree", remove_while_another_user_writes
    )
    layout.finish_deletions()
    assert write_succeeded
    assert not canonical_challenge.exists()


@pytest.mark.parametrize("corruption", ("invalid_utf8", "too_large"))
def test_one_bad_markdown_artifact_does_not_block_startup(tmp_path, caplog, corruption):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    second = "5" * 32
    with database() as db:
        db.execute(
            """INSERT INTO challenges
               (id,workspace_id,name,category,description,created_at,updated_at)
               VALUES(?,?,?,'','','2026-01-01','2026-01-01')""",
            (second, WORKSPACE, "Healthy problem"),
        )
    layout = StorageLayout(settings, database)
    notes = layout.challenge_path(WORKSPACE, CHALLENGE) / "notes.md"
    if corruption == "invalid_utf8":
        notes.write_bytes(b"\xff\xfe")
    else:
        with notes.open("wb") as output:
            output.truncate(8 * 1024 * 1024 + 1)
    resumed = StorageLayout(settings, database)
    assert (resumed.challenge_path(WORKSPACE, second) / "notes.md").is_file()
    assert "readable artifact sync skipped" in caplog.text
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(StorageArtifactError, match="notes.md"):
            resumed.sync_challenge(db, WORKSPACE, CHALLENGE)


@pytest.mark.parametrize("level", ("workspace", "challenge"))
def test_valid_marker_behind_directory_symlink_is_never_followed(tmp_path, level):
    settings, database, owner = environment(tmp_path)
    insert_challenge(database, owner)
    layout = StorageLayout(settings, database)
    target = (
        layout.workspace_path(WORKSPACE)
        if level == "workspace"
        else layout.challenge_path(WORKSPACE, CHALLENGE)
    )
    identity = target / ".ctf-agent-id"
    outside = tmp_path / f"outside-{level}"
    outside.mkdir()
    shutil.copy2(identity, outside / identity.name)
    shutil.rmtree(target)
    try:
        os.symlink(outside, target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(RuntimeError, match="occupied"):
        if level == "workspace":
            layout.workspace_path(WORKSPACE)
        else:
            layout.challenge_path(WORKSPACE, CHALLENGE)
    assert {path.name for path in outside.iterdir()} == {".ctf-agent-id"}
