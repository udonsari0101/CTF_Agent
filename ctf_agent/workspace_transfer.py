"""Versioned, credential-free transfer of workspace data and solver history.

The bundle never reads provider accounts, CTFd connection secrets,
notification settings, live sessions, or worker state. Imported solver jobs
are read-only history, not resumable provider sessions. User text, flags,
attachments and logs may themselves be sensitive; treat the bundle as private.
Remote endpoints are omitted unless explicitly requested.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import uuid
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db import Settings, connect
from .solver_history_transfer import (
    ARCHIVE_PATH as HISTORY_ARCHIVE_PATH,
    HistoryError, export_history, history_digest, import_history,
    validate_descriptor as validate_history_descriptor,
)
from .storage_layout import StorageLayout


FORMAT = "ctf-agent-workspace"
VERSION = 4
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 50_000
CHUNK = 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_UPLOAD_ID = re.compile(r"[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CHALLENGE_FIELDS = (
    "id", "name", "category", "description", "status", "previous_status",
    "completion_source", "flag", "notes", "created_at", "updated_at",
    "remote_mode", "remote",
    "canonical_name", "deleted_at",
)
_WORKSPACE_FIELDS = (
    "id", "name", "description", "flag_format",
    "open_challenge_after_create", "created_at", "updated_at",
)
_STAT_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns") + (
    ("st_ctime_ns",) if os.name != "nt" else ()
)


class TransferError(ValueError):
    """Bundle or source state is invalid; no imported workspace was published."""


def _ensure_import_journal(db: sqlite3.Connection) -> None:
    db.execute(
        """CREATE TABLE IF NOT EXISTS transfer_imports(
           upload_id TEXT PRIMARY KEY,
           owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
           scope TEXT NOT NULL CHECK(scope IN ('workspace','challenge')),
           destination_workspace_id TEXT,
           result_json TEXT NOT NULL,
           created_at TEXT NOT NULL)"""
    )


def _journal_result(db: sqlite3.Connection, owner_user_id: str,
                    upload_id: str, scope: str | None,
                    destination_workspace_id: str | None) -> dict | None:
    row = db.execute(
        """SELECT owner_user_id,scope,destination_workspace_id,result_json
           FROM transfer_imports WHERE upload_id=?""", (upload_id,),
    ).fetchone()
    if row is None:
        return None
    if row["owner_user_id"] != owner_user_id:
        raise TransferError("Upload belongs to another user.")
    if scope is not None and row["scope"] != scope:
        raise TransferError("Upload was imported with a different scope.")
    if destination_workspace_id is not None and (
        row["destination_workspace_id"] != destination_workspace_id
    ):
        raise TransferError("Upload was imported into another workspace.")
    return json.loads(row["result_json"])


def lookup_import(settings: Settings, owner_user_id: str, upload_id: str,
                  *, scope: str | None = None,
                  destination_workspace_id: str | None = None) -> dict | None:
    """Return a committed import result after a lost HTTP response or crash.

    The journal row is committed in the same SQLite transaction as the
    imported workspace/challenge; it never records a partially imported DB.
    """
    if not isinstance(upload_id, str) or not _UPLOAD_ID.fullmatch(upload_id):
        raise TransferError("Invalid upload identifier.")
    if scope not in (None, "workspace", "challenge"):
        raise TransferError("Invalid import scope.")
    if destination_workspace_id is not None and not _ID.fullmatch(destination_workspace_id):
        raise TransferError("Invalid destination workspace identifier.")
    with closing(connect(settings)) as db:
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='transfer_imports'"
        ).fetchone() is None:
            return None
        return _journal_result(db, owner_user_id, upload_id, scope,
                               destination_workspace_id)


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _regular(path: Path, root: Path):
    # A direct file check alone would still follow a replaced parent symlink.
    # The canonical tree consists solely of managed directories.
    if not path.is_relative_to(root):
        raise TransferError("Attachment path leaves managed storage.")
    parent = path.parent
    while parent != root:
        details = parent.lstat()
        if not stat.S_ISDIR(details.st_mode):
            raise TransferError("An attachment parent is not a directory.")
        parent = parent.parent
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode):
        raise TransferError("An attachment is not a regular file.")
    return details


def _same_file(before, after) -> bool:
    return all(getattr(before, key) == getattr(after, key) for key in _STAT_FIELDS)


def _snapshot(db: sqlite3.Connection, owner: str, workspace_id: str) -> dict:
    row = db.execute(
        "SELECT * FROM workspaces WHERE id=? AND owner_user_id=?",
        (workspace_id, owner),
    ).fetchone()
    if row is None:
        raise TransferError("Workspace not found for this user.")
    challenges = db.execute(
        "SELECT * FROM challenges WHERE workspace_id=? ORDER BY created_at,id",
        (workspace_id,),
    ).fetchall()
    has_writeups = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='challenge_writeups'"
    ).fetchone()
    writeups = {
        item["challenge_id"]: item["markdown"]
        for item in db.execute(
            "SELECT challenge_id,markdown FROM challenge_writeups WHERE challenge_id IN "
            "(SELECT id FROM challenges WHERE workspace_id=?)",
            (workspace_id,),
        ).fetchall()
    } if has_writeups else {}
    attachments = db.execute(
        "SELECT * FROM attachments WHERE workspace_id=? ORDER BY challenge_id,created_at,id",
        (workspace_id,),
    ).fetchall()
    relations = db.execute(
        "SELECT prerequisite_id,dependent_id FROM challenge_relations "
        "WHERE workspace_id=? ORDER BY prerequisite_id,dependent_id",
        (workspace_id,),
    ).fetchall()
    has_clone_members = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='challenge_clone_members'"
    ).fetchone()
    clone_members = db.execute(
        """SELECT challenge_id,family_id FROM challenge_clone_members
            WHERE workspace_id=? ORDER BY family_id,challenge_id""",
        (workspace_id,),
    ).fetchall() if has_clone_members else []
    has_shares = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='challenge_evidence_shares'"
    ).fetchone()
    shares = db.execute(
        """SELECT target_challenge_id,source_challenge_id,observation,
                  include_flag,source_updated_at,verified_at
             FROM challenge_evidence_shares WHERE workspace_id=?
            ORDER BY target_challenge_id,source_challenge_id""",
        (workspace_id,),
    ).fetchall() if has_shares else []
    return {
        "workspace": {field: row[field] for field in _WORKSPACE_FIELDS},
        "challenges": [
            {**{field: item[field] for field in _CHALLENGE_FIELDS},
             "writeup_markdown": writeups.get(item["id"])}
            for item in challenges
        ],
        "relations": [dict(item) for item in relations],
        "clone_members": [dict(item) for item in clone_members],
        "evidence_shares": [dict(item) for item in shares],
        "attachments": [
            {field: item[field] for field in (
                "id", "challenge_id", "original_name", "stored_name", "size", "created_at"
            )}
            for item in attachments
        ],
    }


def _source_metadata(settings: Settings, owner: str, workspace_id: str) -> dict:
    with closing(connect(settings)) as db:
        db.execute("BEGIN")
        try:
            return _snapshot(db, owner, workspace_id)
        finally:
            db.rollback()


def _sync_readable(settings: Settings, layout: StorageLayout,
                   owner: str, workspace_id: str,
                   challenge_id: str | None) -> None:
    """Bring editor-visible Markdown into the DB before a source snapshot."""
    with closing(connect(settings)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        owned = db.execute(
            "SELECT 1 FROM workspaces WHERE id=? AND owner_user_id=?",
            (workspace_id, owner),
        ).fetchone()
        if not owned:
            raise TransferError("Workspace not found for this user.")
        if challenge_id is not None:
            ids = [challenge_id]
        else:
            ids = [item[0] for item in db.execute(
                "SELECT id FROM challenges WHERE workspace_id=? ORDER BY id",
                (workspace_id,),
            ).fetchall()]
        for item_id in ids:
            layout.sync_challenge(db, workspace_id, item_id)


def _write_attachment(bundle: zipfile.ZipFile, source: Path, archive_name: str,
                      expected_size: int, root: Path) -> str:
    before = _regular(source, root)
    if before.st_size != expected_size:
        raise TransferError("An attachment changed size during export.")
    digest = hashlib.sha256()
    copied = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            raise TransferError("An attachment changed during export.")
        with (
            os.fdopen(descriptor, "rb", closefd=False) as read,
            bundle.open(archive_name, "w", force_zip64=True) as write,
        ):
            while chunk := read.read(CHUNK):
                copied += len(chunk)
                if copied > expected_size:
                    raise TransferError("An attachment changed size during export.")
                digest.update(chunk)
                write.write(chunk)
        after = os.fstat(descriptor)
        if copied != expected_size or not _same_file(before, after):
            raise TransferError("An attachment changed during export.")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def export_workspace(
    settings: Settings,
    layout: StorageLayout,
    owner_user_id: str,
    workspace_id: str,
    destination: Path,
    *,
    include_remote: bool = False,
    challenge_id: str | None = None,
) -> dict[str, Any]:
    """Write a ZIP64 bundle to a new path; verify source stability before publish.

    The caller should serialize this with workspace writers. File metadata is
    checked before and after streaming, and the database snapshot is compared
    again before publication. The output path must be server-chosen and unique.
    """
    if not _ID.fullmatch(workspace_id):
        raise TransferError("Invalid workspace identifier.")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise TransferError("The export destination already exists.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _sync_readable(settings, layout, owner_user_id, workspace_id, challenge_id)
    snapshot = _source_metadata(settings, owner_user_id, workspace_id)
    if challenge_id is not None:
        if not _ID.fullmatch(challenge_id):
            raise TransferError("Invalid challenge identifier.")
        if not any(item["id"] == challenge_id for item in snapshot["challenges"]):
            raise TransferError("Challenge not found in this workspace.")
        snapshot["challenges"] = [
            item for item in snapshot["challenges"] if item["id"] == challenge_id
        ]
        snapshot["attachments"] = [
            item for item in snapshot["attachments"] if item["challenge_id"] == challenge_id
        ]
        snapshot["relations"] = []
        snapshot["clone_members"] = []
        snapshot["evidence_shares"] = []
    if len(snapshot["attachments"]) > MAX_ENTRIES:
        raise TransferError("Too many attachments for one bundle.")
    free = shutil.disk_usage(destination.parent).free
    raw_size = sum(item["size"] for item in snapshot["attachments"])
    if free - raw_size < settings.storage_min_free_bytes:
        raise TransferError("Insufficient free space to export the bundle.")
    staging = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        bundle_metadata = json.loads(json.dumps(snapshot, ensure_ascii=False))
        for challenge in bundle_metadata["challenges"]:
            if not include_remote:
                challenge["remote"] = ""
                challenge["remote_mode"] = "unknown"
        for item in bundle_metadata["attachments"]:
            name = item["stored_name"]
            if not isinstance(name, str) or not _ID.fullmatch(name):
                raise TransferError("An attachment storage identifier is invalid.")
            item["archive_path"] = f"attachments/{item['id']}"
        with zipfile.ZipFile(staging, "w", compression=zipfile.ZIP_DEFLATED,
                             allowZip64=True, compresslevel=6) as bundle:
            for item in bundle_metadata["attachments"]:
                source = layout.legacy_attachment_path(
                    workspace_id, item["challenge_id"], item["stored_name"]
                )
                item["sha256"] = _write_attachment(
                    bundle, source, item["archive_path"], item["size"],
                    layout.legacy_root,
                )
            try:
                with closing(connect(settings)) as db:
                    history = export_history(db, bundle, owner_user_id, workspace_id, challenge_id)
            except HistoryError as exc:
                raise TransferError(str(exc)) from exc
            manifest = {
                "format": FORMAT,
                "version": VERSION,
                "scope": "challenge" if challenge_id is not None else "workspace",
                "exported_at": _stamp(),
                "included_remote": bool(include_remote),
                "excluded": [
                    "users", "sessions", "provider_accounts", "ctfd_credentials",
                    "telegram_settings", "native_provider_sessions", "worker_state",
                    "retry_checkpoints", "upload_sessions",
                    "peer_evidence_ledger",
                ],
                "solver_history": history,
                **bundle_metadata,
            }
            encoded = json.dumps(manifest, ensure_ascii=False,
                                 separators=(",", ":"), sort_keys=True).encode("utf-8")
            if len(encoded) > MAX_MANIFEST_BYTES:
                raise TransferError("Workspace metadata is too large for one bundle.")
            bundle.writestr("manifest.json", encoded)
        _sync_readable(settings, layout, owner_user_id, workspace_id, challenge_id)
        current = _source_metadata(settings, owner_user_id, workspace_id)
        if challenge_id is not None:
            current["challenges"] = [
                item for item in current["challenges"] if item["id"] == challenge_id
            ]
            current["attachments"] = [
                item for item in current["attachments"] if item["challenge_id"] == challenge_id
            ]
            current["relations"] = []
            current["clone_members"] = []
            current["evidence_shares"] = []
        if current != snapshot:
            raise TransferError("The workspace changed during export; retry.")
        try:
            with closing(connect(settings)) as db:
                if history_digest(db, owner_user_id, workspace_id, challenge_id) != history:
                    raise TransferError("Solver history changed during export; retry.")
        except HistoryError as exc:
            raise TransferError(str(exc)) from exc
        with staging.open("r+b") as source:
            os.fsync(source.fileno())
        # Hard-link publishing never replaces an existing user-selected file.
        os.link(staging, destination)
        return {
            "path": str(destination),
            "workspace_id": workspace_id,
            "scope": "challenge" if challenge_id is not None else "workspace",
            "challenge_count": len(snapshot["challenges"]),
            "attachment_count": len(snapshot["attachments"]),
            "evidence_share_count": len(snapshot["evidence_shares"]),
            "solver_job_count": history["job_count"],
            "solver_event_count": history["event_count"],
            "size": destination.stat().st_size,
        }
    finally:
        staging.unlink(missing_ok=True)


def export_challenge(settings: Settings, layout: StorageLayout, owner_user_id: str,
                     workspace_id: str, challenge_id: str, destination: Path,
                     *, include_remote: bool = False) -> dict[str, Any]:
    """Export one challenge and its files, without unrelated linked challenges."""
    return export_workspace(
        settings, layout, owner_user_id, workspace_id, destination,
        include_remote=include_remote, challenge_id=challenge_id,
    )


def _string(value: Any, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise TransferError(f"Invalid {label} in bundle.")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise TransferError(f"Invalid {label} in bundle.")
    return value


def _validate(bundle: zipfile.ZipFile) -> dict:
    entries = bundle.infolist()
    if len(entries) > MAX_ENTRIES + 2 or len({item.filename for item in entries}) != len(entries):
        raise TransferError("Bundle has duplicate or too many entries.")
    names = {item.filename for item in entries}
    if "manifest.json" not in names:
        raise TransferError("Bundle manifest is missing.")
    info = bundle.getinfo("manifest.json")
    if info.file_size > MAX_MANIFEST_BYTES or info.file_size < 2:
        raise TransferError("Bundle manifest is too large or empty.")
    try:
        manifest = json.loads(bundle.read("manifest.json"))
    except (json.JSONDecodeError, UnicodeDecodeError, RuntimeError,
            zipfile.BadZipFile) as exc:
        raise TransferError("Bundle manifest is not valid JSON.") from exc
    if (not isinstance(manifest, dict) or manifest.get("format") != FORMAT
            or manifest.get("version") not in (1, 2, 3, VERSION)):
        raise TransferError("Unsupported workspace bundle version.")
    mandatory = {
        "format", "version", "scope", "exported_at", "included_remote",
        "excluded", "workspace", "challenges", "relations", "attachments",
    }
    extra = {"solver_history"} if manifest["version"] >= 2 else set()
    required = mandatory | extra
    optional = {"evidence_shares", "clone_members"}
    if not required <= set(manifest) or not set(manifest) <= required | optional:
        raise TransferError("Bundle manifest contains unknown metadata fields.")
    manifest.setdefault("evidence_shares", [])
    manifest.setdefault("clone_members", [])
    if manifest["version"] >= 2:
        try:
            validate_history_descriptor(bundle, manifest["solver_history"])
        except HistoryError as exc:
            raise TransferError(str(exc)) from exc
    if manifest.get("scope", "workspace") not in {"workspace", "challenge"}:
        raise TransferError("Unsupported bundle scope.")
    if not isinstance(manifest["included_remote"], bool):
        raise TransferError("Invalid remote inclusion setting in bundle.")
    if not isinstance(manifest["excluded"], list) or not all(
        isinstance(value, str) for value in manifest["excluded"]
    ):
        raise TransferError("Invalid exclusion manifest.")
    _string(manifest["exported_at"], "export time")
    ws = manifest.get("workspace")
    challenges = manifest.get("challenges")
    attachments = manifest.get("attachments")
    relations = manifest.get("relations")
    shares = manifest["evidence_shares"]
    clone_members = manifest["clone_members"]
    if (not isinstance(ws, dict) or not isinstance(challenges, list)
            or not isinstance(attachments, list) or not isinstance(relations, list)
            or not isinstance(shares, list) or not isinstance(clone_members, list)):
        raise TransferError("Bundle metadata is incomplete.")
    if set(ws) != set(_WORKSPACE_FIELDS):
        raise TransferError("Workspace metadata has unknown fields.")
    if (len(challenges) > MAX_ENTRIES or len(relations) > MAX_ENTRIES
            or len(shares) > MAX_ENTRIES or len(clone_members) > MAX_ENTRIES):
        raise TransferError("Too many challenges, relations, or shares in bundle.")
    _identifier(ws.get("id"), "workspace ID")
    for field in ("name", "description", "created_at", "updated_at"):
        _string(ws.get(field), f"workspace {field}")
    _string(ws.get("flag_format"), "flag format", optional=True)
    if (isinstance(ws.get("open_challenge_after_create"), bool)
            or ws.get("open_challenge_after_create") not in (0, 1)):
        raise TransferError("Invalid workspace option in bundle.")
    ids: set[str] = set()
    for item in challenges:
        if not isinstance(item, dict):
            raise TransferError("Invalid challenge in bundle.")
        legacy_fields = set(_CHALLENGE_FIELDS) - {"canonical_name", "deleted_at"}
        expected_fields = set(_CHALLENGE_FIELDS) if manifest["version"] >= 4 else legacy_fields
        if set(item) != expected_fields | {"writeup_markdown"}:
            raise TransferError("Challenge metadata has unknown fields.")
        if manifest["version"] < 4:
            item["canonical_name"] = None
            item["deleted_at"] = None
        challenge_id = _identifier(item.get("id"), "challenge ID")
        if challenge_id in ids:
            raise TransferError("Duplicate challenge ID in bundle.")
        ids.add(challenge_id)
        for field in ("name", "category", "description", "notes", "created_at", "updated_at", "remote"):
            _string(item.get(field), f"challenge {field}")
        for field in ("flag", "previous_status", "completion_source", "writeup_markdown"):
            _string(item.get(field), f"challenge {field}", optional=True)
        for field in ("canonical_name", "deleted_at"):
            _string(item.get(field), f"challenge {field}", optional=True)
        if item.get("status") not in {"pending", "running", "stopped", "failed", "flag_found", "solved"}:
            raise TransferError("Invalid challenge status in bundle.")
        if item.get("remote_mode") not in {"unknown", "none", "endpoint"}:
            raise TransferError("Invalid remote mode in bundle.")
        if item.get("completion_source") not in (None, "manual", "agent"):
            raise TransferError("Invalid completion source in bundle.")
    seen_clone_members: set[str] = set()
    for item in clone_members:
        if not isinstance(item, dict) or set(item) != {"challenge_id", "family_id"}:
            raise TransferError("Invalid clone lineage in bundle.")
        challenge_id = item["challenge_id"]
        if challenge_id not in ids or challenge_id in seen_clone_members:
            raise TransferError("Orphan or duplicate clone lineage in bundle.")
        _identifier(item["family_id"], "clone family ID")
        seen_clone_members.add(challenge_id)
    expected = {"manifest.json"}
    if manifest["version"] >= 2:
        expected.add(HISTORY_ARCHIVE_PATH)
    attachment_ids: set[str] = set()
    for item in attachments:
        if not isinstance(item, dict):
            raise TransferError("Invalid attachment in bundle.")
        if set(item) != {
            "id", "challenge_id", "original_name", "stored_name", "size",
            "created_at", "archive_path", "sha256",
        }:
            raise TransferError("Attachment metadata has unknown fields.")
        attachment_id = _identifier(item.get("id"), "attachment ID")
        if attachment_id in attachment_ids or item.get("challenge_id") not in ids:
            raise TransferError("Duplicate or orphan attachment in bundle.")
        attachment_ids.add(attachment_id)
        _identifier(item.get("stored_name"), "stored filename")
        _string(item.get("original_name"), "original filename")
        _string(item.get("created_at"), "attachment timestamp")
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > 2**63 - 1:
            raise TransferError("Invalid attachment size in bundle.")
        if item.get("archive_path") != f"attachments/{attachment_id}" or not isinstance(item.get("sha256"), str) or not _SHA256.fullmatch(item["sha256"]):
            raise TransferError("Invalid attachment integrity record in bundle.")
        expected.add(item["archive_path"])
        if item["archive_path"] not in names:
            raise TransferError("Bundle attachment is missing.")
        if bundle.getinfo(item["archive_path"]).file_size != size:
            raise TransferError("Attachment length differs from the manifest.")
    if names != expected:
        raise TransferError("Bundle contains missing or unexpected files.")
    for entry in entries:
        mode = (entry.external_attr >> 16) & 0o170000
        if mode not in (0, stat.S_IFREG):
            raise TransferError("Bundle contains a non-file entry.")
    seen_relations: set[tuple[str, str]] = set()
    for item in relations:
        if not isinstance(item, dict):
            raise TransferError("Invalid relation in bundle.")
        if set(item) != {"prerequisite_id", "dependent_id"}:
            raise TransferError("Relation metadata has unknown fields.")
        pair = (item.get("prerequisite_id"), item.get("dependent_id"))
        if pair[0] not in ids or pair[1] not in ids or pair[0] == pair[1] or pair in seen_relations:
            raise TransferError("Invalid or duplicate relation in bundle.")
        seen_relations.add(pair)
    seen_shares: set[tuple[str, str]] = set()
    relation_edges = {tuple(sorted(edge)) for edge in seen_relations}
    for item in shares:
        if not isinstance(item, dict) or set(item) != {
            "target_challenge_id", "source_challenge_id", "observation",
            "include_flag", "source_updated_at", "verified_at",
        }:
            raise TransferError("Invalid evidence share in bundle.")
        pair = (item["target_challenge_id"], item["source_challenge_id"])
        if (pair[0] not in ids or pair[1] not in ids or pair[0] == pair[1]
                or pair in seen_shares
                or tuple(sorted(pair)) not in relation_edges):
            raise TransferError("Orphan or duplicate evidence share in bundle.")
        seen_shares.add(pair)
        observation = _string(item["observation"], "shared observation")
        if len(observation) > 1200 or (not observation and item["include_flag"] != 1):
            raise TransferError("Invalid shared observation in bundle.")
        if (isinstance(item["include_flag"], bool)
                or item["include_flag"] not in (0, 1)):
            raise TransferError("Invalid flag sharing setting in bundle.")
        _string(item["source_updated_at"], "share source timestamp")
        _string(item["verified_at"], "share verification timestamp")
    if manifest.get("scope") == "challenge" and (len(challenges) != 1 or relations or shares or clone_members):
        raise TransferError("A challenge bundle must contain exactly one challenge.")
    return manifest


def preview_bundle(archive: Path, *, settings: Settings | None = None,
                   owner_user_id: str | None = None,
                   destination_workspace_id: str | None = None) -> dict[str, Any]:
    """Inspect bundle metadata without importing or reading attachment payloads.

    Name collisions are advisory: imported IDs and readable paths are always
    newly allocated. Hashes are checked only by the actual import operation.
    """
    archive = Path(archive)
    try:
        if not stat.S_ISREG(archive.lstat().st_mode):
            raise TransferError("Bundle is not a regular file.")
        with zipfile.ZipFile(archive, "r", allowZip64=True) as bundle:
            manifest = _validate(bundle)
    except (OSError, zipfile.BadZipFile) as exc:
        raise TransferError("Bundle is not a valid ZIP file.") from exc
    shares = manifest["evidence_shares"]
    sizes: dict[str, tuple[int, int]] = {}
    for attachment in manifest["attachments"]:
        prior_count, prior_size = sizes.get(attachment["challenge_id"], (0, 0))
        sizes[attachment["challenge_id"]] = (
            prior_count + 1, prior_size + attachment["size"]
        )
    total = sum(item["size"] for item in manifest["attachments"])
    collisions: list[str] = []
    free_bytes = None
    database_free_bytes = None
    sufficient_space = None
    if settings is not None:
        free_bytes = shutil.disk_usage(settings.data_dir).free
        database_free_bytes = shutil.disk_usage(settings.db_dir).free
        history_size = (manifest.get("solver_history") or {}).get("size", 0)
        sufficient_space = (
            free_bytes - total >= settings.storage_min_free_bytes
            and database_free_bytes - history_size * 3 >= settings.storage_min_free_bytes
        )
        if owner_user_id:
            with closing(connect(settings)) as db:
                if destination_workspace_id:
                    owned = db.execute(
                        "SELECT 1 FROM workspaces WHERE id=? AND owner_user_id=?",
                        (destination_workspace_id, owner_user_id),
                    ).fetchone()
                    if not owned:
                        raise TransferError("Destination workspace not found for this user.")
                    existing = {
                        row[0].casefold() for row in db.execute(
                            "SELECT name FROM challenges WHERE workspace_id=?",
                            (destination_workspace_id,),
                        )
                    }
                    collisions = [
                        item["name"] for item in manifest["challenges"]
                        if item["name"].casefold() in existing
                    ]
                elif db.execute(
                    "SELECT 1 FROM workspaces WHERE owner_user_id=? AND name=? COLLATE NOCASE",
                    (owner_user_id, manifest["workspace"]["name"]),
                ).fetchone():
                    collisions = [manifest["workspace"]["name"]]
    return {
        "scope": manifest.get("scope", "workspace"),
        "version": manifest["version"],
        "name": manifest["workspace"]["name"] if manifest.get("scope") != "challenge"
                else manifest["challenges"][0]["name"],
        "challenge_count": len(manifest["challenges"]),
        "attachment_count": len(manifest["attachments"]),
        "evidence_share_count": len(shares),
        "solver_job_count": (manifest.get("solver_history") or {}).get("job_count", 0),
        "solver_event_count": (manifest.get("solver_history") or {}).get("event_count", 0),
        "solver_guidance_count": (manifest.get("solver_history") or {}).get("guidance_count", 0),
        "flag_share_count": sum(1 for share in shares if share["include_flag"]),
        "flag_shares_require_reapproval": any(share["include_flag"] for share in shares),
        "observations_require_reapproval": any(share["observation"] for share in shares),
        "attachment_bytes": total,
        "archive_bytes": archive.stat().st_size,
        "free_bytes": free_bytes,
        "database_free_bytes": database_free_bytes,
        "sufficient_space": sufficient_space,
        "name_collisions": collisions,
        "remote_endpoints_included": manifest["included_remote"],
        "structural_credentials_excluded": True,
        "free_text_may_contain_secrets": True,
        "integrity": "metadata_only",
        "challenges": [
            {
                "source_id": item["id"], "name": item["name"],
                "category": item["category"], "status": item["status"],
                "has_flag": bool(item["flag"]),
                "has_writeup": bool(item["writeup_markdown"]),
                "attachment_count": sizes.get(item["id"], (0, 0))[0],
                "attachment_bytes": sizes.get(item["id"], (0, 0))[1],
            }
            for item in manifest["challenges"]
        ],
    }


def _copy_from_bundle(bundle: zipfile.ZipFile, item: dict, target: Path) -> None:
    digest = hashlib.sha256()
    count = 0
    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        with bundle.open(item["archive_path"]) as source, target.open("xb") as sink:
            while chunk := source.read(CHUNK):
                count += len(chunk)
                if count > item["size"]:
                    raise TransferError("Attachment exceeds its declared size.")
                digest.update(chunk)
                sink.write(chunk)
            sink.flush()
            os.fsync(sink.fileno())
    except (zipfile.BadZipFile, RuntimeError, EOFError, NotImplementedError) as exc:
        raise TransferError("Attachment ZIP data could not be read.") from exc
    if count != item["size"] or digest.hexdigest() != item["sha256"]:
        raise TransferError("Attachment checksum does not match the manifest.")


def _check_history_storage(settings: Settings, manifest: dict) -> None:
    history = manifest.get("solver_history")
    if not history:
        return
    # SQLite indexes, WAL pages and UTF-8 JSON can take more space than the
    # uncompressed archive. Reserve three times the serialized history size.
    needed = history["size"] * 3
    if shutil.disk_usage(settings.db_dir).free - needed < settings.storage_min_free_bytes:
        raise TransferError("Insufficient database space to import solver history.")


def import_workspace(settings: Settings, layout: StorageLayout, owner_user_id: str,
                     archive: Path, *, source_upload_id: str | None = None) -> dict[str, Any]:
    """Import a checked bundle as a new workspace with new IDs.

    Attachments are staged on the data filesystem, then moved into the
    canonical tree before the database transaction. On failure, only the new
    workspace's paths are cleaned. Crash leftovers are orphaned, never linked
    to an existing workspace, and may be reclaimed by a maintenance task.
    """
    if source_upload_id is not None:
        prior = lookup_import(settings, owner_user_id, source_upload_id,
                              scope="workspace")
        if prior is not None:
            return prior
    archive = Path(archive)
    try:
        details = archive.lstat()
    except OSError as exc:
        raise TransferError("Bundle file could not be read.") from exc
    if not stat.S_ISREG(details.st_mode):
        raise TransferError("Bundle is not a regular file.")
    try:
        bundle_file = zipfile.ZipFile(archive, "r", allowZip64=True)
    except (OSError, zipfile.BadZipFile) as exc:
        raise TransferError("Bundle is not a valid ZIP file.") from exc
    with bundle_file as bundle:
        manifest = _validate(bundle)
        if manifest.get("scope", "workspace") != "workspace":
            raise TransferError("Import this challenge bundle into an existing workspace.")
        _check_history_storage(settings, manifest)
        total = sum(item["size"] for item in manifest["attachments"])
        free = shutil.disk_usage(settings.data_dir).free
        if free - total < settings.storage_min_free_bytes:
            raise TransferError("Insufficient free space to import the bundle.")
        workspace_id = uuid.uuid4().hex
        challenge_ids = {item["id"]: uuid.uuid4().hex for item in manifest["challenges"]}
        attachment_ids = {item["id"]: uuid.uuid4().hex for item in manifest["attachments"]}
        legacy_root = layout.legacy_root
        stage = Path(tempfile.mkdtemp(prefix=".import-", dir=legacy_root))
        canonical = legacy_root / workspace_id
        view: Path | None = None
        published = False
        try:
            for item in manifest["attachments"]:
                target = (stage / "challenges" / challenge_ids[item["challenge_id"]]
                          / "attachments" / attachment_ids[item["id"]])
                _copy_from_bundle(bundle, item, target)
            if canonical.exists() or canonical.is_symlink():
                raise TransferError("Import ID collision; retry.")
            os.replace(stage, canonical)
            stamp = _stamp()
            with closing(connect(settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                if source_upload_id is not None:
                    _ensure_import_journal(db)
                    prior = _journal_result(db, owner_user_id,
                                            source_upload_id, "workspace", None)
                    if prior is not None:
                        return prior
                user = db.execute(
                    "SELECT 1 FROM users WHERE id=? AND active=1", (owner_user_id,)
                ).fetchone()
                if not user:
                    raise TransferError("Import owner is inactive or missing.")
                db.execute(
                    """CREATE TABLE IF NOT EXISTS challenge_writeups(
                       challenge_id TEXT PRIMARY KEY REFERENCES challenges(id) ON DELETE CASCADE,
                       markdown TEXT NOT NULL,created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL)"""
                )
                ws = manifest["workspace"]
                layout.reserve_workspace(db, workspace_id, ws["name"])
                db.execute(
                    """INSERT INTO workspaces(id,name,description,flag_format,
                       open_challenge_after_create,created_at,updated_at,owner_user_id)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (workspace_id, ws["name"], ws["description"], ws["flag_format"],
                     ws["open_challenge_after_create"], stamp, stamp, owner_user_id),
                )
                view = layout.workspace_path(workspace_id, db=db, create=True)
                for item in manifest["challenges"]:
                    new_id = challenge_ids[item["id"]]
                    status = "stopped" if item["status"] == "running" else item["status"]
                    db.execute(
                        """INSERT INTO challenges(
                           id,workspace_id,name,category,description,status,
                           previous_status,completion_source,flag,notes,remote,remote_mode,
                           canonical_name,deleted_at,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (new_id, workspace_id, item["name"], item["category"],
                         item["description"], status,
                         None if item["status"] == "running" else item["previous_status"],
                         item["completion_source"], item["flag"], item["notes"],
                         item["remote"], item["remote_mode"], item["canonical_name"],
                         item["deleted_at"], item["created_at"],
                         item["updated_at"]),
                    )
                    if item["writeup_markdown"] is not None:
                        db.execute(
                            """INSERT INTO challenge_writeups(
                               challenge_id,markdown,created_at,updated_at)
                               VALUES(?,?,?,?)""",
                            (new_id, item["writeup_markdown"], stamp, stamp),
                        )
                for item in manifest["attachments"]:
                    db.execute(
                        """INSERT INTO attachments(id,workspace_id,challenge_id,
                           original_name,stored_name,size,created_at)
                           VALUES(?,?,?,?,?,?,?)""",
                        (attachment_ids[item["id"]], workspace_id,
                         challenge_ids[item["challenge_id"]], item["original_name"],
                         attachment_ids[item["id"]], item["size"], item["created_at"]),
                    )
                for item in manifest["relations"]:
                    first, second = sorted((challenge_ids[item["prerequisite_id"]],
                                            challenge_ids[item["dependent_id"]]))
                    db.execute(
                        """INSERT OR IGNORE INTO challenge_relations(
                           workspace_id,prerequisite_id,dependent_id,created_at)
                           VALUES(?,?,?,?)""",
                        (workspace_id, first, second, stamp),
                    )
                family_ids: dict[str, str] = {
                    item["family_id"]: challenge_ids[item["family_id"]]
                    for item in manifest["clone_members"]
                    if item["family_id"] in challenge_ids
                }
                for item in manifest["clone_members"]:
                    family_ids.setdefault(
                        item["family_id"], challenge_ids[item["challenge_id"]]
                    )
                for item in manifest["clone_members"]:
                    db.execute(
                        """INSERT INTO challenge_clone_members
                           (workspace_id,challenge_id,family_id,created_at)
                           VALUES(?,?,?,?)""",
                        (workspace_id, challenge_ids[item["challenge_id"]],
                         family_ids[item["family_id"]], stamp),
                    )
                for item in manifest["evidence_shares"]:
                    if not item["observation"]:
                        # A Flag-only approval cannot be represented safely
                        # with include_flag reset to zero under the DB CHECK.
                        continue
                    db.execute(
                        """INSERT INTO challenge_evidence_shares(
                           workspace_id,target_challenge_id,source_challenge_id,
                           observation,include_flag,source_updated_at,
                           verified_by_user_id,verified_at,reapproval_required)
                           VALUES(?,?,?,?,?,?,?,?,1)""",
                        (workspace_id, challenge_ids[item["target_challenge_id"]],
                         challenge_ids[item["source_challenge_id"]],
                         item["observation"], 0, item["source_updated_at"],
                         owner_user_id, item["verified_at"]),
                    )
                try:
                    historical_jobs = import_history(
                        db, bundle, manifest.get("solver_history"), owner_user_id,
                        workspace_id, challenge_ids,
                    )
                except HistoryError as exc:
                    raise TransferError(str(exc)) from exc
                for new_id in challenge_ids.values():
                    layout.sync_challenge(db, workspace_id, new_id)
                result = {
                    "workspace_id": workspace_id,
                    "challenge_ids": challenge_ids,
                    "challenge_count": len(challenge_ids),
                    "attachment_count": len(attachment_ids),
                    "evidence_share_count": sum(
                        bool(item["observation"])
                        for item in manifest["evidence_shares"]
                    ),
                    "solver_job_count": historical_jobs,
                }
                if source_upload_id is not None:
                    db.execute(
                        """INSERT INTO transfer_imports(
                           upload_id,owner_user_id,scope,destination_workspace_id,
                           result_json,created_at) VALUES(?,?,'workspace',NULL,?,?)""",
                        (source_upload_id, owner_user_id,
                         json.dumps(result, separators=(",", ":")), stamp),
                    )
            published = True
            return result
        finally:
            if not published:
                try:
                    if view is not None and layout._marker(view, "workspace", workspace_id):
                        shutil.rmtree(view)
                    if canonical.is_dir() and not canonical.is_symlink():
                        shutil.rmtree(canonical)
                except OSError:
                    # A newly created orphan is recoverable; do not hide the
                    # validation/DB error that prevented publication.
                    pass
            if stage.is_dir() and not stage.is_symlink():
                try:
                    shutil.rmtree(stage)
                except OSError:
                    pass


def import_challenge(settings: Settings, layout: StorageLayout, owner_user_id: str,
                     workspace_id: str, archive: Path, *,
                     source_upload_id: str | None = None) -> dict[str, Any]:
    """Import a single-challenge bundle into an existing owned workspace."""
    if not _ID.fullmatch(workspace_id):
        raise TransferError("Invalid destination workspace identifier.")
    if source_upload_id is not None:
        prior = lookup_import(settings, owner_user_id, source_upload_id,
                              scope="challenge",
                              destination_workspace_id=workspace_id)
        if prior is not None:
            return prior
    with closing(connect(settings)) as db:
        owned = db.execute(
            """SELECT 1 FROM workspaces w JOIN users u ON u.id=w.owner_user_id
               WHERE w.id=? AND w.owner_user_id=? AND u.active=1""",
            (workspace_id, owner_user_id),
        ).fetchone()
        if not owned:
            raise TransferError("Destination workspace not found for this user.")
    archive = Path(archive)
    try:
        if not stat.S_ISREG(archive.lstat().st_mode):
            raise TransferError("Bundle is not a regular file.")
        bundle_file = zipfile.ZipFile(archive, "r", allowZip64=True)
    except (OSError, zipfile.BadZipFile) as exc:
        raise TransferError("Bundle is not a valid ZIP file.") from exc
    with bundle_file as bundle:
        manifest = _validate(bundle)
        if manifest.get("scope") != "challenge":
            raise TransferError("A workspace bundle cannot be added as one challenge.")
        _check_history_storage(settings, manifest)
        item = manifest["challenges"][0]
        files = manifest["attachments"]
        total = sum(file["size"] for file in files)
        if shutil.disk_usage(settings.data_dir).free - total < settings.storage_min_free_bytes:
            raise TransferError("Insufficient free space to import the challenge.")
        new_id = uuid.uuid4().hex
        file_ids = {file["id"]: uuid.uuid4().hex for file in files}
        workspace_path = layout.legacy_workspace_path(workspace_id, create=True)
        parent = layout._mkdir_child(workspace_path, "challenges")
        stage = Path(tempfile.mkdtemp(prefix=".import-", dir=parent))
        canonical = parent / new_id
        view: Path | None = None
        published = False
        try:
            for file in files:
                _copy_from_bundle(
                    bundle, file, stage / "attachments" / file_ids[file["id"]]
                )
            if canonical.exists() or canonical.is_symlink():
                raise TransferError("Import ID collision; retry.")
            os.replace(stage, canonical)
            stamp = _stamp()
            with closing(connect(settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                if source_upload_id is not None:
                    _ensure_import_journal(db)
                    prior = _journal_result(db, owner_user_id,
                                            source_upload_id, "challenge",
                                            workspace_id)
                    if prior is not None:
                        return prior
                owned = db.execute(
                    """SELECT w.name FROM workspaces w JOIN users u ON u.id=w.owner_user_id
                       WHERE w.id=? AND w.owner_user_id=? AND u.active=1""",
                    (workspace_id, owner_user_id),
                ).fetchone()
                if not owned:
                    raise TransferError("Destination workspace changed during import.")
                db.execute(
                    """CREATE TABLE IF NOT EXISTS challenge_writeups(
                       challenge_id TEXT PRIMARY KEY REFERENCES challenges(id) ON DELETE CASCADE,
                       markdown TEXT NOT NULL,created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL)"""
                )
                status = "stopped" if item["status"] == "running" else item["status"]
                db.execute(
                    """INSERT INTO challenges(
                       id,workspace_id,name,category,description,status,
                       previous_status,completion_source,flag,notes,remote,remote_mode,
                       canonical_name,deleted_at,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (new_id, workspace_id, item["name"], item["category"],
                     item["description"], status,
                     None if item["status"] == "running" else item["previous_status"],
                     item["completion_source"], item["flag"], item["notes"],
                     item["remote"], item["remote_mode"], item["canonical_name"],
                     item["deleted_at"], item["created_at"],
                     item["updated_at"]),
                )
                if item["writeup_markdown"] is not None:
                    db.execute(
                        """INSERT INTO challenge_writeups(
                           challenge_id,markdown,created_at,updated_at)
                           VALUES(?,?,?,?)""",
                        (new_id, item["writeup_markdown"], stamp, stamp),
                    )
                for file in files:
                    db.execute(
                        """INSERT INTO attachments(id,workspace_id,challenge_id,
                           original_name,stored_name,size,created_at)
                           VALUES(?,?,?,?,?,?,?)""",
                        (file_ids[file["id"]], workspace_id, new_id,
                         file["original_name"], file_ids[file["id"]],
                         file["size"], file["created_at"]),
                    )
                try:
                    historical_jobs = import_history(
                        db, bundle, manifest.get("solver_history"), owner_user_id,
                        workspace_id, {item["id"]: new_id},
                    )
                except HistoryError as exc:
                    raise TransferError(str(exc)) from exc
                db.execute("UPDATE workspaces SET updated_at=? WHERE id=?",
                           (stamp, workspace_id))
                layout.reserve_workspace(db, workspace_id, owned["name"])
                layout.reserve_challenge(db, workspace_id, new_id, item["name"])
                view = layout.challenge_path(
                    workspace_id, new_id, db=db, create=True
                )
                layout.sync_challenge(db, workspace_id, new_id)
                result = {
                    "workspace_id": workspace_id,
                    "challenge_id": new_id,
                    "source_challenge_id": item["id"],
                    "attachment_count": len(files),
                    "solver_job_count": historical_jobs,
                }
                if source_upload_id is not None:
                    db.execute(
                        """INSERT INTO transfer_imports(
                           upload_id,owner_user_id,scope,destination_workspace_id,
                           result_json,created_at) VALUES(?,?,'challenge',?,?,?)""",
                        (source_upload_id, owner_user_id, workspace_id,
                         json.dumps(result, separators=(",", ":")), stamp),
                    )
            published = True
            return result
        finally:
            if not published:
                try:
                    if view is not None and layout._marker(view, "challenge", new_id):
                        shutil.rmtree(view)
                    if canonical.is_dir() and not canonical.is_symlink():
                        shutil.rmtree(canonical)
                except OSError:
                    pass
            if stage.is_dir() and not stage.is_symlink():
                try:
                    shutil.rmtree(stage)
                except OSError:
                    pass
