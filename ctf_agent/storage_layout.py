"""Rollback-safe, human-readable views of persistent CTF files.

The UUID tree under ``/data/workspaces`` remains canonical. This module adds
an independently rebuildable hard-link view under ``/data/workspace_files``.
Older application generations therefore keep working against the same bytes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import threading
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, ContextManager, Iterable


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_INVALID = re.compile(r"[<>:\"/\\|?*]")
_MARKER = ".ctf-agent-id"
_README = "_README.txt"
_TEXT_LIMIT = 8 * 1024 * 1024


class StorageArtifactError(RuntimeError):
    """One directly managed Markdown artifact cannot be synchronized safely."""


def readable_name(value: str, *, fallback: str = "untitled", maximum_bytes: int = 180) -> str:
    """Return a useful Unicode name that is safe on Linux and Windows."""

    normalized = unicodedata.normalize("NFKC", value if isinstance(value, str) else "")
    normalized = "".join(
        "_" if unicodedata.category(character) in {"Cc", "Cf", "Cs"} else character
        for character in normalized
    )
    normalized = _INVALID.sub("_", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip(" .")
    if not normalized or normalized in {".", ".."}:
        normalized = fallback
    if normalized.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        normalized = "_" + normalized
    while len(normalized.encode("utf-8")) > maximum_bytes:
        normalized = normalized[:-1].rstrip(" .")
    return normalized or fallback


def readable_filename(value: str) -> str:
    return readable_name(value, fallback="attachment", maximum_bytes=220)


def storage_component(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or Path(value).name != value
        or "\\" in value
        or len(value.encode("utf-8")) > 240
    ):
        raise ValueError("invalid readable storage component")
    return value


def _numbered_name(preferred: str, number: int) -> str:
    suffix = Path(preferred).suffix
    stem = preferred[: -len(suffix)] if suffix else preferred
    return readable_name(
        f"{stem} ({number}){suffix}",
        fallback=f"attachment ({number})",
        maximum_bytes=220,
    )


def allocate_name(preferred: str, occupied: Iterable[str]) -> str:
    """Allocate with Unicode case folding, matching common file managers."""

    used = {
        unicodedata.normalize("NFKC", item).casefold()
        for item in occupied
        if isinstance(item, str)
    }
    candidate = preferred
    number = 2
    while unicodedata.normalize("NFKC", candidate).casefold() in used:
        candidate = _numbered_name(preferred, number)
        number += 1
    return candidate


def _lstat(path: Path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _is_regular(path: Path) -> bool:
    details = _lstat(path)
    return bool(details and stat.S_ISREG(details.st_mode))


def _same_file(left: Path, right: Path) -> bool:
    try:
        a = os.stat(left, follow_symlinks=False)
        b = os.stat(right, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(a.st_mode) and stat.S_ISREG(b.st_mode) and (
        a.st_dev, a.st_ino
    ) == (b.st_dev, b.st_ino)


class StorageLayout:
    """Manage names, hard links, and Markdown synchronization."""

    def __init__(
        self,
        settings,
        database: Callable[[], ContextManager[sqlite3.Connection]],
    ) -> None:
        self.settings = settings
        self.database = database
        self._deletion_lock = threading.Lock()
        self.legacy_root = Path(settings.data_dir) / "workspaces"
        self.root = Path(settings.data_dir) / "workspace_files"
        self._mkdir(self.legacy_root)
        self._mkdir(self.root)
        self._write_readme()
        self._initialize_tables()
        self.migrate()

    @staticmethod
    def _id(value: str) -> str:
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            raise ValueError("invalid storage identifier")
        return value

    @staticmethod
    def _mkdir(path: Path) -> None:
        details = _lstat(path)
        if details:
            if not stat.S_ISDIR(details.st_mode):
                raise RuntimeError("managed storage directory is not a directory")
            return
        path.mkdir(mode=0o750, parents=True, exist_ok=True)
        try:
            os.chmod(path, 0o750)
        except OSError:
            pass

    @classmethod
    def _mkdir_child(cls, parent: Path, component: str) -> Path:
        storage_component(component)
        parent_info = _lstat(parent)
        if not parent_info or not stat.S_ISDIR(parent_info.st_mode):
            raise RuntimeError("managed storage parent is not a directory")
        target = parent / component
        cls._mkdir(target)
        return target

    @staticmethod
    def _atomic_write(path: Path, payload: bytes, mode: int = 0o640) -> None:
        details = _lstat(path)
        if details and not stat.S_ISREG(details.st_mode):
            raise RuntimeError("managed file path is not a regular file")
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, mode)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as output:
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        if hasattr(os, "O_DIRECTORY"):
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _write_readme(self) -> None:
        path = self.root / _README
        details = _lstat(path)
        if details is not None and not stat.S_ISREG(details.st_mode):
            raise RuntimeError("readable storage README path is unsafe")
        if details is None:
            self._atomic_write(
                path,
                (
                    "CTF Agent workspace files\n\n"
                    "Attachment files are hard links to the application's UUID storage. "
                    "Reading, copying, and in-place editing use the same bytes.\n"
                    "Use the web UI to rename or delete attachments. Files removed from "
                    "this view are restored while their database record exists.\n"
                    "notes.md and writeup.md edits are imported when the challenge is next opened.\n"
                ).encode("utf-8"),
            )

    def _initialize_tables(self) -> None:
        with self.database() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS readable_storage_paths (
                    kind TEXT NOT NULL CHECK(kind IN ('workspace','challenge','attachment')),
                    entity_id TEXT NOT NULL,
                    parent_id TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL,
                    linked INTEGER NOT NULL DEFAULT 0 CHECK(linked IN (0,1)),
                    PRIMARY KEY(kind,entity_id),
                    UNIQUE(kind,parent_id,name COLLATE NOCASE)
                );
                CREATE INDEX IF NOT EXISTS idx_readable_storage_parent
                    ON readable_storage_paths(kind,parent_id);
                CREATE TABLE IF NOT EXISTS readable_text_state (
                    kind TEXT NOT NULL CHECK(kind IN ('notes','writeup')),
                    challenge_id TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    PRIMARY KEY(kind,challenge_id)
                );
                CREATE TABLE IF NOT EXISTS readable_refresh_handoffs (
                    new_attachment_id TEXT PRIMARY KEY,
                    old_attachment_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    readable_name TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_readable_refresh_challenge
                    ON readable_refresh_handoffs(workspace_id,challenge_id);
                CREATE TABLE IF NOT EXISTS readable_delete_handoffs (
                    kind TEXT NOT NULL CHECK(kind IN ('workspace','challenge','attachment')),
                    entity_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL DEFAULT '',
                    stored_name TEXT NOT NULL DEFAULT '',
                    readable_name TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(kind,entity_id)
                );
                """
            )
            columns = {
                row[1] for row in db.execute("PRAGMA table_info(readable_storage_paths)")
            }
            if "linked" not in columns:
                db.execute(
                    "ALTER TABLE readable_storage_paths ADD COLUMN linked INTEGER NOT NULL DEFAULT 0"
                )
            delete_columns = {
                row[1] for row in db.execute(
                    "PRAGMA table_info(readable_delete_handoffs)"
                )
            }
            if "readable_name" not in delete_columns:
                db.execute(
                    """ALTER TABLE readable_delete_handoffs
                       ADD COLUMN readable_name TEXT NOT NULL DEFAULT ''"""
                )

    def plan_refresh_views(
        self,
        db,
        workspace_id: str,
        challenge_id: str,
        old_files: Iterable[dict],
        new_files: Iterable[dict],
    ) -> None:
        """Journal stable-name transfers in the attachment publication commit."""

        reusable: dict[tuple[int, str], list[dict]] = {}
        for item in (dict(row) for row in old_files):
            if not item.get("readable_name"):
                continue
            key = (int(item.get("file_index", -1)), item.get("original_name", ""))
            reusable.setdefault(key, []).append(item)
        db.execute(
            "DELETE FROM readable_refresh_handoffs WHERE workspace_id=? AND challenge_id=?",
            (workspace_id, challenge_id),
        )
        for item in (dict(row) for row in new_files):
            key = (int(item.get("file_index", -1)), item.get("original_name", ""))
            candidates = reusable.get(key) or []
            previous = candidates.pop(0) if candidates else None
            if previous is None:
                continue
            db.execute(
                """INSERT INTO readable_refresh_handoffs(
                       new_attachment_id,old_attachment_id,workspace_id,
                       challenge_id,readable_name
                   ) VALUES(?,?,?,?,?)""",
                (
                    item["id"], previous["attachment_id"], workspace_id,
                    challenge_id, storage_component(previous["readable_name"]),
                ),
            )

    def _recover_refresh_handoffs(
        self,
        db,
        workspace_id: str | None = None,
        challenge_id: str | None = None,
    ) -> None:
        conditions, parameters = [], []
        if workspace_id is not None:
            conditions.append("workspace_id=?")
            parameters.append(workspace_id)
        if challenge_id is not None:
            conditions.append("challenge_id=?")
            parameters.append(challenge_id)
        query = "SELECT * FROM readable_refresh_handoffs"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        for handoff in db.execute(query, parameters).fetchall():
            new_attachment = db.execute(
                """SELECT * FROM attachments
                     WHERE id=? AND workspace_id=? AND challenge_id=?""",
                (
                    handoff["new_attachment_id"], handoff["workspace_id"],
                    handoff["challenge_id"],
                ),
            ).fetchone()
            old_mapping = self._mapping(
                db, "attachment", handoff["old_attachment_id"]
            )
            if not new_attachment or not old_mapping:
                if old_mapping and not db.execute(
                    "SELECT 1 FROM attachments WHERE id=?",
                    (handoff["old_attachment_id"],),
                ).fetchone():
                    self.forget(db, "attachment", handoff["old_attachment_id"])
                db.execute(
                    "DELETE FROM readable_refresh_handoffs WHERE new_attachment_id=?",
                    (handoff["new_attachment_id"],),
                )
                continue
            try:
                readable = self.challenge_path(
                    handoff["workspace_id"], handoff["challenge_id"],
                    db=db, create=True,
                ) / "attachments" / storage_component(handoff["readable_name"])
                self._mkdir(readable.parent)
                old_canonical = self.legacy_attachment_path(
                    handoff["workspace_id"], handoff["challenge_id"],
                    handoff["old_attachment_id"],
                )
                new_canonical = self.legacy_attachment_path(
                    handoff["workspace_id"], handoff["challenge_id"],
                    new_attachment["stored_name"],
                )
                safe_to_publish = (
                    _lstat(readable) is None
                    or _same_file(readable, old_canonical)
                    or _same_file(readable, new_canonical)
                )
                if safe_to_publish and _is_regular(new_canonical):
                    if not _same_file(readable, new_canonical):
                        temporary = readable.with_name(
                            f".{readable.name}.{uuid.uuid4().hex}.handoff"
                        )
                        os.link(new_canonical, temporary, follow_symlinks=False)
                        os.replace(temporary, readable)
                    self.forget(db, "attachment", handoff["old_attachment_id"])
                    self.forget(db, "attachment", handoff["new_attachment_id"])
                    db.execute(
                        """INSERT INTO readable_storage_paths
                           (kind,entity_id,parent_id,name,linked)
                           VALUES('attachment',?,?,?,1)""",
                        (
                            handoff["new_attachment_id"],
                            handoff["challenge_id"],
                            handoff["readable_name"],
                        ),
                    )
                elif not db.execute(
                    "SELECT 1 FROM attachments WHERE id=?",
                    (handoff["old_attachment_id"],),
                ).fetchone():
                    # An unrelated external object now occupies the old view.
                    # Preserve it and release only the stale database mapping.
                    self.forget(db, "attachment", handoff["old_attachment_id"])
            finally:
                db.execute(
                    "DELETE FROM readable_refresh_handoffs WHERE new_attachment_id=?",
                    (handoff["new_attachment_id"],),
                )

    def plan_delete(
        self,
        db,
        kind: str,
        entity_id: str,
        workspace_id: str,
        *,
        challenge_id: str = "",
        stored_name: str = "",
        readable_name: str = "",
    ) -> None:
        if kind not in {"workspace", "challenge", "attachment"}:
            raise ValueError("invalid storage deletion kind")
        self._id(entity_id)
        self._id(workspace_id)
        if challenge_id:
            self._id(challenge_id)
        if stored_name:
            storage_component(stored_name)
        if readable_name:
            storage_component(readable_name)
        db.execute(
            """INSERT OR REPLACE INTO readable_delete_handoffs(
                   kind,entity_id,workspace_id,challenge_id,stored_name,readable_name
               ) VALUES(?,?,?,?,?,?)""",
            (
                kind, entity_id, workspace_id, challenge_id, stored_name,
                readable_name,
            ),
        )

    @staticmethod
    def _delete_entity_exists(db, row) -> bool:
        table = {
            "workspace": "workspaces",
            "challenge": "challenges",
            "attachment": "attachments",
        }[row["kind"]]
        return bool(
            db.execute(
                f"SELECT 1 FROM {table} WHERE id=?", (row["entity_id"],)
            ).fetchone()
        )

    def _delete_readable_target(self, db, row) -> Path | None:
        if row["kind"] != "attachment" or not row["readable_name"]:
            return None
        try:
            return self.challenge_path(
                row["workspace_id"], row["challenge_id"], db=db
            ) / "attachments" / storage_component(row["readable_name"])
        except (RuntimeError, ValueError):
            return None

    def _delete_handoff_files(self, row, readable: Path | None = None) -> None:
        if row["kind"] == "workspace":
            target = self.legacy_workspace_path(row["workspace_id"])
        elif row["kind"] == "challenge":
            target = self.legacy_challenge_path(
                row["workspace_id"], row["challenge_id"]
            )
        else:
            target = self.legacy_attachment_path(
                row["workspace_id"], row["challenge_id"], row["stored_name"]
            )
        details = _lstat(target)
        if not details:
            return
        if row["kind"] == "attachment":
            if not stat.S_ISREG(details.st_mode):
                raise RuntimeError("canonical deletion target is unsafe")
            if readable is not None and _same_file(readable, target):
                try:
                    readable.unlink()
                except FileNotFoundError:
                    pass
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            return
        if not stat.S_ISDIR(details.st_mode):
            raise RuntimeError("canonical deletion directory is unsafe")
        try:
            shutil.rmtree(target)
        except FileNotFoundError:
            pass

    @staticmethod
    def _delete_fingerprint(row) -> tuple[str, ...]:
        return tuple(
            row[key]
            for key in (
                "kind", "entity_id", "workspace_id", "challenge_id",
                "stored_name", "readable_name",
            )
        )

    def _recover_deletions(self, db) -> None:
        for row in db.execute("SELECT * FROM readable_delete_handoffs").fetchall():
            if self._delete_entity_exists(db, row):
                db.execute(
                    "DELETE FROM readable_delete_handoffs WHERE kind=? AND entity_id=?",
                    (row["kind"], row["entity_id"]),
                )
                continue
            self._delete_handoff_files(row, self._delete_readable_target(db, row))
            db.execute(
                "DELETE FROM readable_delete_handoffs WHERE kind=? AND entity_id=?",
                (row["kind"], row["entity_id"]),
            )

    def finish_deletions(self) -> None:
        """Finish committed deletes without holding SQLite while removing large trees."""

        with self._deletion_lock:
            pending: list[tuple[dict, Path | None]] = []
            with self.database() as db:
                db.execute("BEGIN IMMEDIATE")
                for row in db.execute(
                    "SELECT * FROM readable_delete_handoffs"
                ).fetchall():
                    if self._delete_entity_exists(db, row):
                        db.execute(
                            "DELETE FROM readable_delete_handoffs WHERE kind=? AND entity_id=?",
                            (row["kind"], row["entity_id"]),
                        )
                        continue
                    pending.append(
                        (dict(row), self._delete_readable_target(db, row))
                    )

            first_error: BaseException | None = None
            for row, readable in pending:
                try:
                    self._delete_handoff_files(row, readable)
                except BaseException as exc:
                    first_error = first_error or exc
                    logging.getLogger(__name__).exception(
                        "durable storage deletion remains pending kind=%s entity=%s",
                        row["kind"], row["entity_id"],
                    )
                    continue
                with self.database() as db:
                    db.execute("BEGIN IMMEDIATE")
                    current = db.execute(
                        "SELECT * FROM readable_delete_handoffs WHERE kind=? AND entity_id=?",
                        (row["kind"], row["entity_id"]),
                    ).fetchone()
                    if (
                        current
                        and self._delete_fingerprint(current)
                        == self._delete_fingerprint(row)
                        and not self._delete_entity_exists(db, current)
                    ):
                        db.execute(
                            "DELETE FROM readable_delete_handoffs WHERE kind=? AND entity_id=?",
                            (row["kind"], row["entity_id"]),
                        )

            with self.database() as db:
                db.execute("BEGIN IMMEDIATE")
                self._cleanup_stale_records(db)
            if first_error is not None:
                raise first_error

    @staticmethod
    def _mapping(db, kind: str, entity_id: str):
        return db.execute(
            "SELECT name,parent_id,linked FROM readable_storage_paths WHERE kind=? AND entity_id=?",
            (kind, entity_id),
        ).fetchone()

    @staticmethod
    def _mapped_names(db, kind: str, parent_id: str) -> list[str]:
        return [
            row[0]
            for row in db.execute(
                "SELECT name FROM readable_storage_paths WHERE kind=? AND parent_id=?",
                (kind, parent_id),
            )
        ]

    @staticmethod
    def _disk_names(parent: Path) -> list[str]:
        if _lstat(parent) is None:
            return []
        if not stat.S_ISDIR(os.lstat(parent).st_mode):
            raise RuntimeError("readable storage parent is not a directory")
        return [entry.name for entry in os.scandir(parent)]

    @staticmethod
    def _marker_identity(path: Path) -> tuple[str, str] | None:
        directory = _lstat(path)
        if directory is None or not stat.S_ISDIR(directory.st_mode):
            return None
        marker = path / _MARKER
        if not _is_regular(marker):
            return None
        try:
            value = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, TypeError):
            return None
        if (
            not isinstance(value, dict)
            or value.get("kind") not in {"workspace", "challenge"}
            or not isinstance(value.get("id"), str)
            or not _SAFE_ID.fullmatch(value["id"])
        ):
            return None
        return value["kind"], value["id"]

    @classmethod
    def _marker(cls, path: Path, kind: str, entity_id: str) -> bool:
        return cls._marker_identity(path) == (kind, entity_id)

    def _find_marked(self, parent: Path, kind: str, entity_id: str) -> str | None:
        if _lstat(parent) is None:
            return None
        for entry in os.scandir(parent):
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False) and self._marker(path, kind, entity_id):
                return entry.name
        return None

    def _mark(self, path: Path, kind: str, entity_id: str) -> None:
        self._mkdir(path)
        marker = path / _MARKER
        payload = json.dumps({"kind": kind, "id": entity_id}, sort_keys=True).encode()
        if _is_regular(marker):
            if marker.read_bytes() == payload:
                return
            raise RuntimeError("readable storage marker belongs to another record")
        if _lstat(marker) is not None:
            raise RuntimeError("readable storage marker is unsafe")
        self._atomic_write(marker, payload, mode=0o600)

    def _reserve(
        self,
        db,
        kind: str,
        entity_id: str,
        parent_id: str,
        label: str,
        parent_path: Path,
        *,
        filename: bool = False,
    ) -> str:
        entity_id = self._id(entity_id)
        parent_id = "" if not parent_id else self._id(parent_id)
        existing = self._mapping(db, kind, entity_id)
        if existing:
            return storage_component(existing["name"])
        recovered = None if filename else self._find_marked(parent_path, kind, entity_id)
        if recovered:
            candidate = storage_component(recovered)
        else:
            preferred = readable_filename(label) if filename else readable_name(
                label, fallback=kind
            )
            occupied = self._mapped_names(db, kind, parent_id) + self._disk_names(parent_path)
            candidate = allocate_name(preferred, occupied)
        db.execute(
            "INSERT INTO readable_storage_paths(kind,entity_id,parent_id,name) VALUES(?,?,?,?)",
            (kind, entity_id, parent_id, candidate),
        )
        return candidate

    def reserve_workspace(self, db, workspace_id: str, label: str) -> str:
        return self._reserve(db, "workspace", workspace_id, "", label, self.root)

    def reserve_challenge(self, db, workspace_id: str, challenge_id: str, label: str) -> str:
        workspace = self.workspace_path(workspace_id, db=db, create=True)
        return self._reserve(
            db, "challenge", challenge_id, workspace_id, label, workspace
        )

    def reserve_attachment(
        self, db, workspace_id: str, challenge_id: str, attachment_id: str, label: str
    ) -> str:
        parent = self.challenge_path(workspace_id, challenge_id, db=db, create=True) / "attachments"
        self._mkdir(parent)
        canonical = self.legacy_attachment_path(
            workspace_id, challenge_id, attachment_id, create_parent=False
        )
        if _is_regular(canonical):
            for entry in os.scandir(parent):
                target = Path(entry.path)
                if entry.is_file(follow_symlinks=False) and _same_file(canonical, target):
                    owner = db.execute(
                        """SELECT entity_id FROM readable_storage_paths
                             WHERE kind='attachment' AND parent_id=?
                               AND name=? COLLATE NOCASE""",
                        (challenge_id, entry.name),
                    ).fetchone()
                    owner_exists = bool(
                        owner
                        and db.execute(
                            "SELECT 1 FROM attachments WHERE id=? AND challenge_id=?",
                            (owner["entity_id"], challenge_id),
                        ).fetchone()
                    )
                    # A refresh publishes the new UUID rows before replacing the
                    # readable link.  If the process dies between replacing the
                    # link and committing the mapping transfer, the old UUID's
                    # orphan mapping still owns this name.  Reclaim only when
                    # the bytes prove the link belongs to the new canonical file
                    # and no live attachment owns the mapping.
                    if not owner_exists:
                        db.execute(
                            "DELETE FROM readable_storage_paths WHERE kind='attachment' AND entity_id=?",
                            (attachment_id,),
                        )
                        if owner:
                            db.execute(
                                "DELETE FROM readable_storage_paths WHERE kind='attachment' AND entity_id=?",
                                (owner["entity_id"],),
                            )
                        db.execute(
                            """INSERT INTO readable_storage_paths
                               (kind,entity_id,parent_id,name,linked)
                               VALUES('attachment',?,?,?,1)""",
                            (attachment_id, challenge_id, entry.name),
                        )
                        return entry.name
                    if owner["entity_id"] == attachment_id:
                        db.execute(
                            """UPDATE readable_storage_paths SET linked=1
                                 WHERE kind='attachment' AND entity_id=?""",
                            (attachment_id,),
                        )
                        return entry.name
        return self._reserve(
            db, "attachment", attachment_id, challenge_id, label, parent, filename=True
        )

    def workspace_path(self, workspace_id: str, *, db=None, create: bool = False) -> Path:
        workspace_id = self._id(workspace_id)
        context = None
        if db is None:
            context = self.database()
            db = context.__enter__()
        try:
            row = self._mapping(db, "workspace", workspace_id)
            if not row:
                raise ValueError("workspace readable path is not initialized")
            target = self.root / storage_component(row["name"])
            if create:
                while _lstat(target) is not None and not self._marker(
                    target, "workspace", workspace_id
                ):
                    occupied = self._mapped_names(db, "workspace", "") + self._disk_names(self.root)
                    name = allocate_name(row["name"], occupied)
                    db.execute(
                        "UPDATE readable_storage_paths SET name=? WHERE kind='workspace' AND entity_id=?",
                        (name, workspace_id),
                    )
                    target = self.root / name
                self._mark(target, "workspace", workspace_id)
            elif _lstat(target) and not self._marker(target, "workspace", workspace_id):
                raise RuntimeError("workspace readable path is occupied")
            return target
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def challenge_path(
        self, workspace_id: str, challenge_id: str, *, db=None, create: bool = False
    ) -> Path:
        challenge_id = self._id(challenge_id)
        context = None
        if db is None:
            context = self.database()
            db = context.__enter__()
        try:
            workspace = self.workspace_path(workspace_id, db=db, create=create)
            row = self._mapping(db, "challenge", challenge_id)
            if not row or row["parent_id"] != workspace_id:
                raise ValueError("challenge readable path is not initialized")
            target = workspace / storage_component(row["name"])
            if create:
                while _lstat(target) is not None and not self._marker(
                    target, "challenge", challenge_id
                ):
                    occupied = self._mapped_names(db, "challenge", workspace_id) + self._disk_names(workspace)
                    name = allocate_name(row["name"], occupied)
                    db.execute(
                        "UPDATE readable_storage_paths SET name=? WHERE kind='challenge' AND entity_id=?",
                        (name, challenge_id),
                    )
                    target = workspace / name
                self._mark(target, "challenge", challenge_id)
            elif _lstat(target) and not self._marker(target, "challenge", challenge_id):
                raise RuntimeError("challenge readable path is occupied")
            return target
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def readable_attachment_path(
        self, workspace_id: str, challenge_id: str, attachment_id: str, *, db=None
    ) -> Path:
        context = None
        if db is None:
            context = self.database()
            db = context.__enter__()
        try:
            row = self._mapping(db, "attachment", self._id(attachment_id))
            if not row or row["parent_id"] != challenge_id:
                raise ValueError("attachment readable path is not initialized")
            return self.challenge_path(workspace_id, challenge_id, db=db) / "attachments" / storage_component(row["name"])
        finally:
            if context is not None:
                context.__exit__(None, None, None)

    def legacy_workspace_path(self, workspace_id: str, *, create: bool = False) -> Path:
        target = self.legacy_root / self._id(workspace_id)
        if create:
            target = self._mkdir_child(self.legacy_root, self._id(workspace_id))
        return target

    def legacy_challenge_path(
        self, workspace_id: str, challenge_id: str, *, create: bool = False
    ) -> Path:
        workspace = self.legacy_workspace_path(workspace_id, create=create)
        if create:
            challenges = self._mkdir_child(workspace, "challenges")
            target = self._mkdir_child(challenges, self._id(challenge_id))
        else:
            target = workspace / "challenges" / self._id(challenge_id)
        return target

    def legacy_attachment_path(
        self,
        workspace_id: str,
        challenge_id: str,
        stored_name: str,
        *,
        create_parent: bool = False,
    ) -> Path:
        challenge = self.legacy_challenge_path(
            workspace_id, challenge_id, create=create_parent
        )
        if create_parent:
            parent = self._mkdir_child(challenge, "attachments")
        else:
            parent = challenge / "attachments"
        return parent / storage_component(stored_name)

    @staticmethod
    def _preserve(path: Path, recovery: Path, label: str) -> Path:
        StorageLayout._mkdir(recovery)
        number = 1
        while True:
            target = recovery / f"{label}.{number}"
            if _lstat(target) is None:
                os.link(path, target, follow_symlinks=False)
                return target
            number += 1

    def ensure_attachment_view(
        self, db, workspace_id: str, challenge_id: str, attachment, *, view_wins: bool | None = None
    ) -> Path:
        """Reconcile one hard link without overwriting or following external paths."""

        attachment_id = attachment["id"]
        canonical = self.legacy_attachment_path(
            workspace_id, challenge_id, attachment["stored_name"], create_parent=True
        )
        name = self.reserve_attachment(
            db, workspace_id, challenge_id, attachment_id, attachment["original_name"]
        )
        mapping = self._mapping(db, "attachment", attachment_id)
        if view_wins is None:
            view_wins = bool(mapping and mapping["linked"])
        parent = self.challenge_path(
            workspace_id, challenge_id, db=db, create=True
        ) / "attachments"
        self._mkdir(parent)
        while True:
            target = parent / storage_component(name)
            canonical_info, target_info = _lstat(canonical), _lstat(target)
            if canonical_info and not stat.S_ISREG(canonical_info.st_mode):
                raise RuntimeError("canonical attachment is not a regular file")
            if target_info and not stat.S_ISREG(target_info.st_mode):
                occupied = self._mapped_names(db, "attachment", challenge_id) + self._disk_names(parent)
                name = allocate_name(readable_filename(attachment["original_name"]), occupied)
                db.execute(
                    "UPDATE readable_storage_paths SET name=? WHERE kind='attachment' AND entity_id=?",
                    (name, attachment_id),
                )
                continue
            if not canonical_info and not target_info:
                return target
            if not canonical_info:
                if view_wins:
                    os.link(target, canonical, follow_symlinks=False)
                else:
                    occupied = (
                        self._mapped_names(db, "attachment", challenge_id)
                        + self._disk_names(parent)
                    )
                    name = allocate_name(
                        readable_filename(attachment["original_name"]), occupied
                    )
                    db.execute(
                        """UPDATE readable_storage_paths SET name=?
                             WHERE kind='attachment' AND entity_id=?""",
                        (name, attachment_id),
                    )
                    continue
            elif not target_info:
                try:
                    os.link(canonical, target, follow_symlinks=False)
                except FileExistsError:
                    continue
            elif not _same_file(canonical, target):
                if view_wins:
                    recovery = self.legacy_challenge_path(workspace_id, challenge_id, create=True) / ".readable-recovery"
                    self._preserve(canonical, recovery, attachment_id)
                    temporary = canonical.with_name(f".{canonical.name}.{uuid.uuid4().hex}.link")
                    os.link(target, temporary, follow_symlinks=False)
                    os.replace(temporary, canonical)
                else:
                    occupied = self._mapped_names(db, "attachment", challenge_id) + self._disk_names(parent)
                    name = allocate_name(readable_filename(attachment["original_name"]), occupied)
                    db.execute(
                        "UPDATE readable_storage_paths SET name=? WHERE kind='attachment' AND entity_id=?",
                        (name, attachment_id),
                    )
                    continue
            size = canonical.stat().st_size
            if "size" in attachment.keys() and size != int(attachment["size"]):
                db.execute("UPDATE attachments SET size=? WHERE id=?", (size, attachment_id))
            db.execute(
                "UPDATE readable_storage_paths SET linked=1 WHERE kind='attachment' AND entity_id=?",
                (attachment_id,),
            )
            return target

    def reconcile_refresh_views(
        self,
        workspace_id: str,
        challenge_id: str,
        old_files: Iterable[dict],
        new_files: Iterable[dict],
    ) -> None:
        """Publish refreshed links after the CTFd database commit.

        An unchanged remote filename keeps its readable path. If that path was
        atomically replaced outside the app, the external file is preserved and
        the refreshed attachment uses its already reserved numbered name.
        """

        old = [dict(item) for item in old_files]
        new = [dict(item) for item in new_files]
        reusable: dict[tuple[int, str], list[dict]] = {}
        for item in old:
            key = (int(item.get("file_index", -1)), item.get("original_name", ""))
            reusable.setdefault(key, []).append(item)
        used_old: set[str] = set()
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            self._recover_refresh_handoffs(db, workspace_id, challenge_id)
            for item in new:
                attachment = db.execute(
                    "SELECT * FROM attachments WHERE id=? AND workspace_id=? AND challenge_id=?",
                    (item["id"], workspace_id, challenge_id),
                ).fetchone()
                if not attachment:
                    continue
                key = (int(item.get("file_index", -1)), item.get("original_name", ""))
                candidates = reusable.get(key) or []
                previous = candidates.pop(0) if candidates else None
                reused = False
                if previous and previous.get("readable_name"):
                    old_canonical = self.legacy_attachment_path(
                        workspace_id, challenge_id, previous["stored_name"]
                    )
                    readable = self.challenge_path(
                        workspace_id, challenge_id, db=db, create=True
                    ) / "attachments" / storage_component(previous["readable_name"])
                    new_canonical = self.legacy_attachment_path(
                        workspace_id, challenge_id, attachment["stored_name"]
                    )
                    if _same_file(readable, old_canonical) and _is_regular(new_canonical):
                        temporary = readable.with_name(
                            f".{readable.name}.{uuid.uuid4().hex}.link"
                        )
                        os.link(new_canonical, temporary, follow_symlinks=False)
                        os.replace(temporary, readable)
                        try:
                            self.forget(db, "attachment", previous["attachment_id"])
                            self.forget(db, "attachment", item["id"])
                            db.execute(
                                "INSERT INTO readable_storage_paths(kind,entity_id,parent_id,name,linked) VALUES('attachment',?,?,?,1)",
                                (item["id"], challenge_id, previous["readable_name"]),
                            )
                        except BaseException:
                            rollback = readable.with_name(
                                f".{readable.name}.{uuid.uuid4().hex}.rollback"
                            )
                            os.link(old_canonical, rollback, follow_symlinks=False)
                            os.replace(rollback, readable)
                            raise
                        used_old.add(previous["attachment_id"])
                        reused = True
                if not reused:
                    self.ensure_attachment_view(
                        db, workspace_id, challenge_id, attachment,
                        view_wins=False,
                    )
            for previous in old:
                if previous["attachment_id"] in used_old:
                    continue
                if previous.get("readable_name"):
                    readable = self.challenge_path(
                        workspace_id, challenge_id, db=db
                    ) / "attachments" / storage_component(previous["readable_name"])
                    old_canonical = self.legacy_attachment_path(
                        workspace_id, challenge_id, previous["stored_name"]
                    )
                    if _same_file(readable, old_canonical):
                        readable.unlink()
                self.forget(db, "attachment", previous["attachment_id"])

    @staticmethod
    def _digest(payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _decode_text(path: Path) -> bytes:
        details = _lstat(path)
        if not details or not stat.S_ISREG(details.st_mode):
            raise StorageArtifactError(
                f"{path.name} must be a regular file and cannot be a symlink."
            )
        if details.st_size > _TEXT_LIMIT:
            raise StorageArtifactError(f"{path.name} exceeds the 8 MiB text limit.")
        try:
            payload = path.read_bytes()
            payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StorageArtifactError(f"{path.name} must be valid UTF-8 text.") from exc
        except OSError as exc:
            raise StorageArtifactError(f"{path.name} could not be read safely.") from exc
        return payload

    @staticmethod
    def _state(db, kind: str, challenge_id: str):
        return db.execute(
            "SELECT content_sha256,mtime_ns FROM readable_text_state WHERE kind=? AND challenge_id=?",
            (kind, challenge_id),
        ).fetchone()

    @staticmethod
    def _record_state(db, kind: str, challenge_id: str, path: Path, payload: bytes) -> None:
        try:
            mtime = path.stat(follow_symlinks=False).st_mtime_ns
        except OSError as exc:
            raise StorageArtifactError(
                f"{path.name} metadata could not be read safely."
            ) from exc
        db.execute(
            """INSERT INTO readable_text_state(kind,challenge_id,content_sha256,mtime_ns)
               VALUES(?,?,?,?) ON CONFLICT(kind,challenge_id) DO UPDATE SET
               content_sha256=excluded.content_sha256,mtime_ns=excluded.mtime_ns""",
            (kind, challenge_id, hashlib.sha256(payload).hexdigest(), mtime),
        )

    def _preserve_text(self, path: Path, label: str, payload: bytes) -> Path:
        number = 1
        while True:
            target = path.with_name(f"{path.stem}.{label}-{number}{path.suffix}")
            if _lstat(target) is None:
                self._write_artifact(target, payload)
                return target
            number += 1

    def _write_artifact(self, path: Path, payload: bytes) -> None:
        try:
            self._atomic_write(path, payload)
        except (OSError, RuntimeError) as exc:
            raise StorageArtifactError(
                f"{path.name} could not be written safely."
            ) from exc

    def _initialize_text(self, db, kind: str, challenge_id: str, path: Path, content: str) -> None:
        desired = content.encode("utf-8")
        details = _lstat(path)
        if details and not stat.S_ISREG(details.st_mode):
            raise StorageArtifactError(
                f"{path.name} must be a regular file and cannot be a symlink."
            )
        if details:
            current = self._decode_text(path)
            if current != desired:
                self._preserve_text(path, "external", current)
                self._write_artifact(path, desired)
        else:
            self._write_artifact(path, desired)
        self._record_state(db, kind, challenge_id, path, desired)

    def _sync_text(self, db, kind: str, challenge_id: str, path: Path, db_content: str) -> str:
        if _lstat(path) is None:
            payload = db_content.encode("utf-8")
            self._write_artifact(path, payload)
            self._record_state(db, kind, challenge_id, path, payload)
            return db_content
        file_payload = self._decode_text(path)
        file_content = file_payload.decode("utf-8")
        db_payload = db_content.encode("utf-8")
        state = self._state(db, kind, challenge_id)
        if not state:
            if file_payload != db_payload:
                self._preserve_text(path, "external", file_payload)
                self._write_artifact(path, db_payload)
                file_payload = db_payload
            self._record_state(db, kind, challenge_id, path, file_payload)
            return db_content
        baseline = state["content_sha256"]
        file_changed = self._digest(file_payload) != baseline
        db_changed = self._digest(db_payload) != baseline
        if file_changed:
            if db_changed and db_payload != file_payload:
                self._preserve_text(path, "database", db_payload)
            self._record_state(db, kind, challenge_id, path, file_payload)
            return file_content
        if db_changed:
            self._write_artifact(path, db_payload)
            self._record_state(db, kind, challenge_id, path, db_payload)
        return db_content

    def sync_challenge(self, db, workspace_id: str, challenge_id: str) -> None:
        challenge = db.execute(
            "SELECT id,name,notes FROM challenges WHERE id=? AND workspace_id=?",
            (challenge_id, workspace_id),
        ).fetchone()
        if not challenge:
            return
        workspace = db.execute(
            "SELECT name FROM workspaces WHERE id=?", (workspace_id,)
        ).fetchone()
        if not workspace:
            return
        self.reserve_workspace(db, workspace_id, workspace["name"])
        self.reserve_challenge(db, workspace_id, challenge_id, challenge["name"])
        path = self.challenge_path(workspace_id, challenge_id, db=db, create=True)
        notes = self._sync_text(db, "notes", challenge_id, path / "notes.md", challenge["notes"] or "")
        if notes != (challenge["notes"] or ""):
            timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            db.execute(
                "UPDATE challenges SET notes=?,updated_at=? WHERE id=? AND workspace_id=?",
                (notes, timestamp, challenge_id, workspace_id),
            )
        has_writeups = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='challenge_writeups'"
        ).fetchone()
        writeup = (
            db.execute(
                "SELECT markdown FROM challenge_writeups WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            if has_writeups
            else None
        )
        if writeup:
            markdown = self._sync_text(
                db, "writeup", challenge_id, path / "writeup.md", writeup["markdown"]
            )
            if markdown != writeup["markdown"]:
                timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
                db.execute(
                    "UPDATE challenge_writeups SET markdown=?,updated_at=? WHERE challenge_id=?",
                    (markdown, timestamp, challenge_id),
                )
            from .writeups import merge_generated_writeup
            merged_notes = merge_generated_writeup(
                notes, markdown, writeup["markdown"]
            )
            if merged_notes != notes:
                timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
                db.execute(
                    "UPDATE challenges SET notes=?,updated_at=? WHERE id=? AND workspace_id=?",
                    (merged_notes, timestamp, challenge_id, workspace_id),
                )
                notes_payload = merged_notes.encode("utf-8")
                self._write_artifact(path / "notes.md", notes_payload)
                self._record_state(
                    db, "notes", challenge_id, path / "notes.md", notes_payload
                )
        for attachment in db.execute(
            "SELECT * FROM attachments WHERE workspace_id=? AND challenge_id=? ORDER BY created_at,id",
            (workspace_id, challenge_id),
        ).fetchall():
            self.ensure_attachment_view(db, workspace_id, challenge_id, attachment)

    def remove_attachment_view(
        self, db, workspace_id: str, challenge_id: str, attachment
    ) -> Path | None:
        """Remove only a mapped readable file before its database row commits away."""

        mapping = self._mapping(db, "attachment", attachment["id"])
        if not mapping or mapping["parent_id"] != challenge_id:
            return None
        target = self.challenge_path(
            workspace_id, challenge_id, db=db
        ) / "attachments" / storage_component(mapping["name"])
        canonical = self.legacy_attachment_path(
            workspace_id, challenge_id, attachment["stored_name"]
        )
        details = _lstat(target)
        if details and stat.S_ISREG(details.st_mode) and _same_file(
            target, canonical
        ):
            target.unlink()
        return target

    def remove_challenge_view(
        self, db, workspace_id: str, challenge_id: str
    ) -> Path | None:
        """Remove managed files first while rollback can still rebuild them."""

        try:
            target = self.challenge_path(workspace_id, challenge_id, db=db)
        except ValueError:
            return None
        for attachment in db.execute(
            "SELECT * FROM attachments WHERE workspace_id=? AND challenge_id=?",
            (workspace_id, challenge_id),
        ).fetchall():
            self.remove_attachment_view(
                db, workspace_id, challenge_id, attachment
            )
        for kind in ("notes", "writeup"):
            path = target / f"{kind}.md"
            if self._state(db, kind, challenge_id) and _is_regular(path):
                path.unlink()
        # Keep identity markers through the database commit. If that commit
        # rolls back, the next sync rebuilds every removed managed file at the
        # same readable path. Unknown files and directories are never removed.
        return target

    def remove_workspace_view(self, db, workspace_id: str) -> Path | None:
        try:
            target = self.workspace_path(workspace_id, db=db)
        except ValueError:
            return None
        for challenge in db.execute(
            "SELECT id FROM challenges WHERE workspace_id=?", (workspace_id,)
        ).fetchall():
            self.remove_challenge_view(db, workspace_id, challenge["id"])
        return target

    def finalize_deleted_view(
        self, path: Path | None, kind: str, entity_id: str, *, recursive: bool = False
    ) -> None:
        """Detach verified markers after deletion while preserving unknown content."""

        if path is None or not self._marker(path, kind, entity_id):
            return
        if recursive and kind == "workspace":
            for entry in list(os.scandir(path)):
                child = Path(entry.path)
                identity = (
                    self._marker_identity(child)
                    if entry.is_dir(follow_symlinks=False)
                    else None
                )
                if identity and identity[0] == "challenge":
                    self.finalize_deleted_view(child, *identity)
        if kind == "challenge":
            attachments = path / "attachments"
            details = _lstat(attachments)
            if details and stat.S_ISDIR(details.st_mode):
                try:
                    attachments.rmdir()
                except OSError:
                    pass
        marker = path / _MARKER
        if self._marker(path, kind, entity_id):
            marker.unlink()
        try:
            path.rmdir()
        except OSError:
            pass

    def _cleanup_stale_records(self, db) -> None:
        live_workspaces = {
            row[0] for row in db.execute("SELECT id FROM workspaces")
        }
        live_challenges = {
            row[0] for row in db.execute("SELECT id FROM challenges")
        }
        for entry in list(os.scandir(self.root)):
            workspace_path = Path(entry.path)
            identity = (
                self._marker_identity(workspace_path)
                if entry.is_dir(follow_symlinks=False)
                else None
            )
            if not identity or identity[0] != "workspace":
                continue
            if identity[1] not in live_workspaces:
                self.finalize_deleted_view(
                    workspace_path, "workspace", identity[1], recursive=True
                )
                continue
            for child in list(os.scandir(workspace_path)):
                challenge_path = Path(child.path)
                challenge_identity = (
                    self._marker_identity(challenge_path)
                    if child.is_dir(follow_symlinks=False)
                    else None
                )
                if (
                    challenge_identity
                    and challenge_identity[0] == "challenge"
                    and challenge_identity[1] not in live_challenges
                ):
                    self.finalize_deleted_view(
                        challenge_path, "challenge", challenge_identity[1]
                    )
        db.execute(
            """DELETE FROM readable_storage_paths
                 WHERE kind='workspace'
                   AND entity_id NOT IN (SELECT id FROM workspaces)"""
        )
        db.execute(
            """DELETE FROM readable_storage_paths
                 WHERE kind='challenge'
                   AND entity_id NOT IN (SELECT id FROM challenges)"""
        )
        db.execute(
            """DELETE FROM readable_storage_paths
                 WHERE kind='attachment'
                   AND entity_id NOT IN (SELECT id FROM attachments)"""
        )
        db.execute(
            """DELETE FROM readable_text_state
                 WHERE challenge_id NOT IN (SELECT id FROM challenges)"""
        )

    def migrate(self) -> None:
        """Build or repair the view without moving any canonical UUID file."""

        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            self._recover_refresh_handoffs(db)
            self._recover_deletions(db)
            self._cleanup_stale_records(db)
            for workspace in db.execute(
                "SELECT id,name FROM workspaces ORDER BY created_at,id"
            ).fetchall():
                self.reserve_workspace(db, workspace["id"], workspace["name"])
                self.workspace_path(workspace["id"], db=db, create=True)
                for challenge in db.execute(
                    "SELECT id FROM challenges WHERE workspace_id=? ORDER BY created_at,id",
                    (workspace["id"],),
                ).fetchall():
                    try:
                        self.sync_challenge(db, workspace["id"], challenge["id"])
                    except StorageArtifactError as exc:
                        logging.getLogger(__name__).warning(
                            "readable artifact sync skipped workspace=%s challenge=%s: %s",
                            workspace["id"], challenge["id"], exc,
                        )

    def write_notes(self, workspace_id: str, challenge_id: str, content: str) -> None:
        self._write_text("notes", workspace_id, challenge_id, content)

    def write_writeup(self, workspace_id: str, challenge_id: str, content: str) -> None:
        self._write_text("writeup", workspace_id, challenge_id, content)

    def _write_text(self, kind: str, workspace_id: str, challenge_id: str, content: str) -> None:
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            path = self.challenge_path(workspace_id, challenge_id, db=db, create=True) / f"{kind}.md"
            payload = content.encode("utf-8")
            self._write_artifact(path, payload)
            self._record_state(db, kind, challenge_id, path, payload)

    def remove_writeup(self, workspace_id: str, challenge_id: str) -> None:
        with self.database() as db:
            db.execute("BEGIN IMMEDIATE")
            path = self.challenge_path(workspace_id, challenge_id, db=db) / "writeup.md"
            details = _lstat(path)
            if details and not stat.S_ISREG(details.st_mode):
                raise StorageArtifactError(
                    "writeup.md must be a regular file and cannot be a symlink."
                )
            path.unlink(missing_ok=True)
            db.execute(
                "DELETE FROM readable_text_state WHERE kind='writeup' AND challenge_id=?",
                (challenge_id,),
            )

    @staticmethod
    def forget(db, kind: str, entity_id: str) -> None:
        db.execute(
            "DELETE FROM readable_storage_paths WHERE kind=? AND entity_id=?",
            (kind, entity_id),
        )

    def forget_challenge(self, db, challenge_id: str) -> None:
        db.execute(
            "DELETE FROM readable_storage_paths WHERE kind='attachment' AND parent_id=?",
            (challenge_id,),
        )
        self.forget(db, "challenge", challenge_id)
        db.execute(
            "DELETE FROM readable_text_state WHERE challenge_id=?", (challenge_id,)
        )

    def forget_workspace(self, db, workspace_id: str) -> None:
        challenge_ids = [
            row[0]
            for row in db.execute(
                "SELECT id FROM challenges WHERE workspace_id=?", (workspace_id,)
            )
        ]
        for challenge_id in challenge_ids:
            self.forget_challenge(db, challenge_id)
        self.forget(db, "workspace", workspace_id)


__all__ = [
    "StorageArtifactError",
    "StorageLayout",
    "allocate_name",
    "readable_filename",
    "readable_name",
    "storage_component",
]
