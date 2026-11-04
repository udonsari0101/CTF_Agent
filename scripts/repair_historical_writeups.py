"""Conservatively remove historical standalone service-submit lines.

This is an offline maintenance tool. Stop the web, solver and updater services
before applying a plan. The dry run writes only hashes and identifiers to its
plan file; the apply run creates a private SQLite and readable-file backup.

Example (inside an image with the application package available)::

    python /app/scripts/repair_historical_writeups.py \
      --database /database/sqlite/ctf_agent.sqlite3 --data-dir /data \
      --challenge-id ID1 --challenge-id ID2 --challenge-id ID3 \
      --plan /database/sqlite/backups/writeup-repair-plan.json
    python /app/scripts/repair_historical_writeups.py \
      --database /database/sqlite/ctf_agent.sqlite3 --data-dir /data \
      --plan /database/sqlite/backups/writeup-repair-plan.json \
      --backup-dir /database/sqlite/backups --apply --confirm-stopped

No write-up body, Flag or removed command is printed or placed in the plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctf_agent.storage_layout import StorageLayout, storage_component
from ctf_agent.writeup_publication import contains_internal_operation
from ctf_agent.writeups import (
    GENERATED_WRITEUP_END,
    GENERATED_WRITEUP_START,
    generated_writeup_block,
    merge_generated_writeup,
)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_STANDALONE_SUBMIT = re.compile(r"^[ \t]*(?:\$[ \t]+)?submit-flag(?:[ \t]+.*)?$")
_TEXT_LIMIT = 8 * 1024 * 1024


class RepairError(RuntimeError):
    """An expected preflight failure with a non-sensitive reason."""


def _sha(payload: bytes | str) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_id(value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise RepairError("invalid challenge identifier")
    return value


def _regular(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_size > _TEXT_LIMIT:
            raise RepairError("readable Markdown file is unsafe or oversized")
        payload = path.read_bytes()
        payload.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise RepairError("readable Markdown file cannot be read safely") from exc
    return payload, details


def _directory(path: Path) -> None:
    try:
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise RepairError("readable storage directory is unsafe")
    except OSError as exc:
        raise RepairError("readable storage directory is missing") from exc


def _without_submission(markdown: str) -> tuple[str, int]:
    lines = markdown.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines)
               if _STANDALONE_SUBMIT.fullmatch(line.rstrip("\r\n"))]
    if len(matches) > 1:
        raise RepairError("more than one standalone submission line requires review")
    if not matches:
        if contains_internal_operation(markdown):
            raise RepairError("non-standalone internal operation requires review")
        return markdown, 0
    clean = "".join(line for index, line in enumerate(lines) if index != matches[0])
    if not clean.strip() or contains_internal_operation(clean):
        raise RepairError("other internal content requires review")
    return clean, 1


def _clean_notes(notes: str, old: str, clean: str) -> str:
    if old == clean:
        if contains_internal_operation(notes):
            raise RepairError("notes still contain an internal operation")
        return notes
    previous = generated_writeup_block(old)
    updated = generated_writeup_block(clean)
    start_count = notes.count(GENERATED_WRITEUP_START)
    end_count = notes.count(GENERATED_WRITEUP_END)
    if start_count or end_count:
        if start_count != 1 or end_count != 1:
            raise RepairError("notes have ambiguous legacy write-up markers")
        result = merge_generated_writeup(notes, clean, old)
    elif previous and notes.count(previous) == 1:
        result = merge_generated_writeup(notes, clean, old)
    elif updated and notes.count(updated) == 1 and not contains_internal_operation(notes):
        result = notes
    elif not notes:
        result = updated
    else:
        raise RepairError("notes copy cannot be identified without manual review")
    if contains_internal_operation(result):
        raise RepairError("notes still contain an internal operation")
    return result


@dataclass
class FileSnapshot:
    path: Path
    payload: bytes
    mtime_ns: int
    mode: int
    uid: int
    gid: int

    @property
    def digest(self) -> str:
        return _sha(self.payload)


@dataclass
class Candidate:
    challenge_id: str
    workspace_id: str
    markdown: str
    cleaned_markdown: str
    notes: str
    cleaned_notes: str
    removed_lines: int
    files: dict[str, FileSnapshot]

    def plan_record(self) -> dict[str, object]:
        return {
            "challenge_id": self.challenge_id,
            "workspace_id": self.workspace_id,
            "markdown_sha256": _sha(self.markdown),
            "cleaned_markdown_sha256": _sha(self.cleaned_markdown),
            "notes_sha256": _sha(self.notes),
            "cleaned_notes_sha256": _sha(self.cleaned_notes),
            "removed_lines": self.removed_lines,
            "files": {
                kind: {"sha256": snapshot.digest, "mtime_ns": snapshot.mtime_ns}
                for kind, snapshot in self.files.items()
            },
        }


def _snapshot(db: sqlite3.Connection, data_dir: Path, challenge_id: str) -> Candidate:
    challenge_id = _safe_id(challenge_id)
    row = db.execute(
        """SELECT w.markdown,c.notes,c.workspace_id,c.status,c.completion_source
             FROM challenge_writeups w JOIN challenges c ON c.id=w.challenge_id
            WHERE w.challenge_id=?""",
        (challenge_id,),
    ).fetchone()
    if row is None or row["status"] != "solved" or row["completion_source"] != "agent":
        raise RepairError("target is not an agent-solved canonical write-up")
    workspace_id = _safe_id(row["workspace_id"])
    clean, removed = _without_submission(row["markdown"])
    clean_notes = _clean_notes(row["notes"], row["markdown"], clean)
    mappings = {
        kind: db.execute(
            "SELECT name,parent_id FROM readable_storage_paths WHERE kind=? AND entity_id=?",
            (kind, workspace_id if kind == "workspace" else challenge_id),
        ).fetchone()
        for kind in ("workspace", "challenge")
    }
    if not mappings["workspace"] or not mappings["challenge"]:
        raise RepairError("readable storage mapping is missing")
    if mappings["challenge"]["parent_id"] != workspace_id:
        raise RepairError("readable storage mapping belongs to another workspace")
    root = data_dir / "workspace_files"
    workspace = root / storage_component(mappings["workspace"]["name"])
    challenge = workspace / storage_component(mappings["challenge"]["name"])
    for path in (root, workspace, challenge):
        _directory(path)
    if not StorageLayout._marker(workspace, "workspace", workspace_id):
        raise RepairError("workspace readable marker does not match")
    if not StorageLayout._marker(challenge, "challenge", challenge_id):
        raise RepairError("challenge readable marker does not match")
    files = {}
    for kind, content in (("writeup", row["markdown"]), ("notes", row["notes"])):
        path = challenge / f"{kind}.md"
        payload, details = _regular(path)
        if payload != content.encode("utf-8"):
            raise RepairError("readable Markdown differs from canonical database text")
        state = db.execute(
            """SELECT content_sha256,mtime_ns FROM readable_text_state
                WHERE kind=? AND challenge_id=?""",
            (kind, challenge_id),
        ).fetchone()
        if not state or state["content_sha256"] != _sha(payload) or state["mtime_ns"] != details.st_mtime_ns:
            raise RepairError("readable Markdown has an unrecorded edit")
        files[kind] = FileSnapshot(
            path, payload, details.st_mtime_ns,
            stat.S_IMODE(details.st_mode), details.st_uid, details.st_gid,
        )
    return Candidate(
        challenge_id, workspace_id, row["markdown"], clean,
        row["notes"], clean_notes, removed, files,
    )


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def _replace_file(
    snapshot: FileSnapshot, payload: bytes, *, restore_mtime: bool = False,
    require_original_owner: bool = True,
) -> None:
    """Use the storage writer while retaining the original app-writable owner."""

    details = snapshot.path.lstat()
    if require_original_owner and (
        not stat.S_ISREG(details.st_mode)
        or (details.st_uid, details.st_gid, stat.S_IMODE(details.st_mode))
        != (snapshot.uid, snapshot.gid, snapshot.mode)
    ):
        raise RepairError("readable Markdown ownership or mode changed")
    StorageLayout._atomic_write(snapshot.path, payload, mode=snapshot.mode)
    current = snapshot.path.lstat()
    if hasattr(os, "chown") and (current.st_uid, current.st_gid) != (snapshot.uid, snapshot.gid):
        os.chown(snapshot.path, snapshot.uid, snapshot.gid)
    os.chmod(snapshot.path, snapshot.mode)
    if restore_mtime:
        os.utime(snapshot.path, ns=(snapshot.mtime_ns, snapshot.mtime_ns))


def _plan(database: Path, data_dir: Path, ids: list[str], path: Path) -> dict:
    db = _connect(database)
    try:
        rows = [_snapshot(db, data_dir, challenge_id).plan_record() for challenge_id in ids]
    finally:
        db.close()
    plan = {
        "format": 1,
        "database": str(database),
        "data_dir": str(data_dir),
        "targets": rows,
    }
    _write_new(path, (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return plan


def _read_plan(path: Path, database: Path, data_dir: Path) -> dict:
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RepairError("plan cannot be read") from exc
    if not isinstance(plan, dict) or plan.get("format") != 1:
        raise RepairError("plan format is unsupported")
    if plan.get("database") != str(database) or plan.get("data_dir") != str(data_dir):
        raise RepairError("plan paths differ from apply paths")
    rows = plan.get("targets")
    if not isinstance(rows, list) or not rows:
        raise RepairError("plan has no targets")
    ids = [_safe_id(row.get("challenge_id")) for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or len(set(ids)) != len(ids):
        raise RepairError("plan targets are invalid or duplicated")
    digest = re.compile(r"^[0-9a-f]{64}$")
    for row in rows:
        if not _IDENTIFIER.fullmatch(str(row.get("workspace_id", ""))):
            raise RepairError("plan workspace is invalid")
        for key in ("markdown_sha256", "cleaned_markdown_sha256",
                    "notes_sha256", "cleaned_notes_sha256"):
            if not digest.fullmatch(str(row.get(key, ""))):
                raise RepairError("plan digest is invalid")
        if row.get("removed_lines") not in (0, 1):
            raise RepairError("plan line count is invalid")
        files = row.get("files")
        if not isinstance(files, dict) or set(files) != {"writeup", "notes"}:
            raise RepairError("plan file states are invalid")
        for value in files.values():
            if not isinstance(value, dict) or not digest.fullmatch(str(value.get("sha256", ""))):
                raise RepairError("plan file digest is invalid")
            if not isinstance(value.get("mtime_ns"), int) or value["mtime_ns"] < 0:
                raise RepairError("plan file timestamp is invalid")
    return plan


def _status(current: Candidate, planned: dict) -> str:
    if current.workspace_id != planned.get("workspace_id"):
        raise RepairError("target workspace changed since dry run")
    original = (
        _sha(current.markdown) == planned.get("markdown_sha256")
        and _sha(current.notes) == planned.get("notes_sha256")
        and current.removed_lines == planned.get("removed_lines")
        and all(
            current.files[kind].digest == planned.get("files", {}).get(kind, {}).get("sha256")
            and current.files[kind].mtime_ns == planned.get("files", {}).get(kind, {}).get("mtime_ns")
            for kind in ("writeup", "notes")
        )
        and _sha(current.cleaned_markdown) == planned.get("cleaned_markdown_sha256")
        and _sha(current.cleaned_notes) == planned.get("cleaned_notes_sha256")
    )
    if original:
        return "pending" if current.removed_lines else "already_clean"
    already = (
        current.removed_lines == 0
        and _sha(current.markdown) == planned.get("cleaned_markdown_sha256")
        and _sha(current.notes) == planned.get("cleaned_notes_sha256")
        and current.files["writeup"].digest == planned.get("cleaned_markdown_sha256")
        and current.files["notes"].digest == planned.get("cleaned_notes_sha256")
    )
    if already:
        return "already_clean"
    raise RepairError("target changed since dry run")


def _backup(db_path: Path, backup_dir: Path, candidates: list[Candidate]) -> Path:
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if backup_dir.is_symlink():
        raise RepairError("backup directory is a symlink")
    backup_dir.chmod(0o700)
    folder = backup_dir / ("writeup-repair-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex)
    folder.mkdir(mode=0o700)
    destination = folder / "database.sqlite3"
    with closing(sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)) as source:
        with closing(sqlite3.connect(destination)) as target:
            source.backup(target)
            if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RepairError("database backup failed integrity check")
    destination.chmod(0o600)
    for candidate in candidates:
        for kind, snapshot in candidate.files.items():
            _write_new(folder / f"{candidate.challenge_id}-{kind}.md", snapshot.payload)
    _write_new(folder / "IN_PROGRESS", b"Restore the database and Markdown backups before starting the service if this file remains.\n")
    return folder


def _apply(database: Path, data_dir: Path, plan: dict, backup_dir: Path) -> dict:
    db = _connect(database)
    folder: Path | None = None
    written: list[FileSnapshot] = []
    committed = False
    try:
        db.execute("BEGIN IMMEDIATE")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='solver_slots'"
        ).fetchone() and db.execute("SELECT 1 FROM solver_slots LIMIT 1").fetchone():
            raise RepairError("solver slots are still active")
        candidates = [_snapshot(db, data_dir, row["challenge_id"]) for row in plan["targets"]]
        pending = [candidate for candidate, row in zip(candidates, plan["targets"])
                   if _status(candidate, row) == "pending"]
        if not pending:
            db.rollback()
            return {"mode": "apply", "updated": 0, "already_clean": len(candidates)}
        folder = _backup(database, backup_dir, pending)
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for candidate in pending:
            for snapshot in candidate.files.values():
                current_payload, current_details = _regular(snapshot.path)
                if current_payload != snapshot.payload or current_details.st_mtime_ns != snapshot.mtime_ns:
                    raise RepairError("readable Markdown changed during apply")
            edited = db.execute(
                """UPDATE challenge_writeups SET markdown=?,updated_at=?
                    WHERE challenge_id=? AND markdown=?""",
                (candidate.cleaned_markdown, timestamp, candidate.challenge_id, candidate.markdown),
            )
            if edited.rowcount != 1:
                raise RepairError("canonical write-up changed during apply")
            if candidate.cleaned_notes != candidate.notes:
                edited = db.execute(
                    """UPDATE challenges SET notes=?,updated_at=? WHERE id=? AND notes=?""",
                    (candidate.cleaned_notes, timestamp, candidate.challenge_id, candidate.notes),
                )
                if edited.rowcount != 1:
                    raise RepairError("challenge notes changed during apply")
            for kind, content in (("writeup", candidate.cleaned_markdown),
                                  ("notes", candidate.cleaned_notes)):
                snapshot = candidate.files[kind]
                payload = content.encode("utf-8")
                if payload != snapshot.payload:
                    written.append(snapshot)
                    _replace_file(snapshot, payload)
                    StorageLayout._record_state(db, kind, candidate.challenge_id, snapshot.path, payload)
        db.commit()
        committed = True
        for candidate in pending:
            refreshed = _snapshot(db, data_dir, candidate.challenge_id)
            if refreshed.removed_lines or _sha(refreshed.markdown) != _sha(candidate.cleaned_markdown):
                raise RepairError("post-apply verification failed")
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RepairError("database post-apply integrity check failed")
        (folder / "IN_PROGRESS").unlink()
        return {
            "mode": "apply", "updated": len(pending),
            "already_clean": len(candidates) - len(pending), "backup": str(folder),
        }
    except BaseException:
        if not committed:
            db.rollback()
            restored = True
            for snapshot in reversed(written):
                try:
                    _replace_file(
                        snapshot, snapshot.payload, restore_mtime=True,
                        require_original_owner=False,
                    )
                except BaseException:
                    restored = False
            if folder is not None and restored:
                (folder / "IN_PROGRESS").unlink(missing_ok=True)
        if folder is not None:
            print(f"Backup folder: {folder}", file=sys.stderr)
        raise
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--challenge-id", action="append", default=[])
    parser.add_argument("--expected-count", type=int, default=3)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-stopped", action="store_true",
                        help="Confirm web, solver and updater services are stopped")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        database = args.database.resolve(strict=True)
        data_dir = args.data_dir.resolve(strict=True)
        plan_path = args.plan.resolve(strict=False)
        if not stat.S_ISREG(database.lstat().st_mode):
            raise RepairError("database is not a regular file")
        _directory(data_dir)
        if args.apply:
            if not args.confirm_stopped:
                raise RepairError("service stop confirmation is required for apply")
            if args.challenge_id:
                raise RepairError("apply reads target identifiers only from the plan")
            plan = _read_plan(plan_path, database, data_dir)
            if len(plan["targets"]) != args.expected_count or args.backup_dir is None:
                raise RepairError("target count or backup directory is invalid")
            result = _apply(database, data_dir, plan, args.backup_dir.resolve(strict=False))
        else:
            ids = [_safe_id(value) for value in args.challenge_id]
            if len(ids) != args.expected_count or len(set(ids)) != len(ids):
                raise RepairError("expected distinct challenge identifiers were not provided")
            if args.backup_dir is not None:
                raise RepairError("backup directory is used only during apply")
            if not plan_path.parent.is_dir():
                raise RepairError("plan parent directory does not exist")
            plan = _plan(database, data_dir, ids, plan_path)
            result = {
                "mode": "dry-run",
                "targets": len(plan["targets"]),
                "candidate_lines": sum(row["removed_lines"] for row in plan["targets"]),
                "challenge_ids": ids,
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    except RepairError as exc:
        print(f"Write-up maintenance stopped: {exc}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error, ValueError):
        # Even errors must never echo Markdown, Flags, database content or tokens.
        print("Write-up maintenance stopped; inspect the plan, mappings and backup state.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
