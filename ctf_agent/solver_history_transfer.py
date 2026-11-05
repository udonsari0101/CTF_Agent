"""Stream credential-free solver history through workspace ZIP bundles.

Imported jobs are terminal, read-only history. Provider credentials, native
session archives, retry checkpoints, worker state and delivery hooks stay out
of the bundle, so an imported log can never resume as a live process.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import uuid
import zipfile
from collections import Counter
from typing import Any, Callable, Iterator


ARCHIVE_PATH = "solver-history.jsonl"
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 2_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TERMINAL = {"completed", "cancelled", "failed", "refused", "needs_input"}
_OPEN = {"queued", "staging", "awaiting_credential", "running", "flag_found", "writing", "cleanup_blocked"}

# These are display and timing fields only. Never export account_id, credentials,
# native session archives, retry checkpoints, process IDs or notification state.
JOB_FIELDS = (
    "id", "challenge_id", "job_mode", "account_label", "provider", "auth_kind",
    "model", "reasoning_effort", "ultra_escalation_mode", "ultra_source_job_id",
    "ultra_auto_attempted", "ultracode", "max_reasoning_available", "service_tier",
    "codex_version", "codex_runtime_sha256", "claude_version", "claude_runtime_sha256",
    "status", "previous_challenge_status", "last_event_sequence", "agents_json",
    "context_usage_json", "flag", "writeup_markdown", "private_notes",
    "continuation_mode", "continuation_source_job_id", "continuation_confirmed",
    "writeup_instruction", "writeup_locale", "source_writeup_sha256",
    "source_solver_job_id", "challenge_input_sha256", "challenge_base_sha256",
    "challenge_description", "remote_mode", "flag_rejected_at", "error_json",
    "created_at", "claimed_at", "staged_at", "running_at", "first_activity_at",
    "flag_at", "writeup_at", "updated_at", "released_at",
)
GUIDANCE_FIELDS = (
    "id", "job_id", "message", "requested_delivery", "status",
    "provider_delivery", "error_code", "created_at", "staged_at", "delivered_at",
)


class HistoryError(ValueError):
    pass


def _json_line(kind: str, data: dict[str, Any]) -> bytes:
    payload = json.dumps({"type": kind, "data": data}, ensure_ascii=False,
                         separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_RECORD_BYTES:
        raise HistoryError("A solver history record is too large to transfer.")
    return payload


def _emit(db: sqlite3.Connection, owner: str, workspace_id: str,
          challenge_id: str | None, sink: Callable[[bytes], Any]) -> dict[str, Any]:
    digest = hashlib.sha256()
    counts: Counter[str] = Counter()
    size = 0

    def write(kind: str, data: dict[str, Any]) -> None:
        nonlocal size
        payload = _json_line(kind, data)
        size += len(payload)
        digest.update(payload)
        sink(payload)
        counts[kind] += 1
        if sum(counts.values()) > MAX_RECORDS:
            raise HistoryError("Too many solver history records in one bundle.")

    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='solver_jobs'").fetchone()
    if exists:
        # Historical jobs may outlive a deleted challenge. A transfer can only
        # remap jobs belonging to challenges present in this bundle.
        query = ("SELECT j.* FROM solver_jobs j JOIN challenges c "
                 "ON c.id=j.challenge_id AND c.workspace_id=j.workspace_id "
                 "WHERE j.owner_user_id=? AND j.workspace_id=?")
        params: tuple[Any, ...] = (owner, workspace_id)
        if challenge_id is not None:
            query += " AND j.challenge_id=?"
            params += (challenge_id,)
        for job in db.execute(query + " ORDER BY j.created_at,j.id", params):
            write("job", {field: job[field] for field in JOB_FIELDS})
            for event in db.execute(
                "SELECT sequence,kind,event_json,created_at FROM solver_job_events "
                "WHERE job_id=? ORDER BY sequence", (job["id"],),
            ):
                write("event", {"job_id": job["id"], **dict(event)})
            for guidance in db.execute(
                "SELECT * FROM solver_job_guidance WHERE job_id=? ORDER BY created_at,id",
                (job["id"],),
            ):
                write("guidance", {field: guidance[field] for field in GUIDANCE_FIELDS})
    return {
        "archive_path": ARCHIVE_PATH, "size": size, "sha256": digest.hexdigest(),
        "job_count": counts["job"], "event_count": counts["event"],
        "guidance_count": counts["guidance"],
    }


def export_history(db: sqlite3.Connection, bundle: zipfile.ZipFile, owner: str,
                   workspace_id: str, challenge_id: str | None) -> dict[str, Any]:
    db.execute("BEGIN")
    try:
        with bundle.open(ARCHIVE_PATH, "w", force_zip64=True) as sink:
            return _emit(db, owner, workspace_id, challenge_id, sink.write)
    finally:
        db.rollback()


def history_digest(db: sqlite3.Connection, owner: str, workspace_id: str,
                   challenge_id: str | None) -> dict[str, Any]:
    db.execute("BEGIN")
    try:
        return _emit(db, owner, workspace_id, challenge_id, lambda _: None)
    finally:
        db.rollback()


def validate_descriptor(bundle: zipfile.ZipFile, descriptor: Any) -> None:
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "archive_path", "size", "sha256", "job_count", "event_count", "guidance_count"
    } or descriptor["archive_path"] != ARCHIVE_PATH:
        raise HistoryError("Solver history metadata is invalid.")
    for key in ("size", "job_count", "event_count", "guidance_count"):
        value = descriptor[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HistoryError("Solver history length or count is invalid.")
    if sum(descriptor[key] for key in ("job_count", "event_count", "guidance_count")) > MAX_RECORDS:
        raise HistoryError("Solver history contains too many records.")
    if not isinstance(descriptor["sha256"], str) or not _SHA.fullmatch(descriptor["sha256"]):
        raise HistoryError("Solver history digest is invalid.")
    try:
        info = bundle.getinfo(ARCHIVE_PATH)
    except KeyError as exc:
        raise HistoryError("Solver history file is missing.") from exc
    if info.file_size != descriptor["size"]:
        raise HistoryError("Solver history length differs from its manifest.")


def _read(bundle: zipfile.ZipFile, descriptor: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    digest = hashlib.sha256()
    counts: Counter[str] = Counter()
    size = 0
    try:
        with bundle.open(ARCHIVE_PATH) as source:
            while True:
                line = source.readline(MAX_RECORD_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_RECORD_BYTES or not line.endswith(b"\n"):
                    raise HistoryError("Solver history has an oversized or partial record.")
                size += len(line)
                if size > descriptor["size"]:
                    raise HistoryError("Solver history exceeds its declared length.")
                digest.update(line)
                try:
                    entry = json.loads(line)
                except (UnicodeError, ValueError) as exc:
                    raise HistoryError("Solver history contains invalid JSON.") from exc
                if not isinstance(entry, dict) or set(entry) != {"type", "data"}:
                    raise HistoryError("Solver history record has unknown fields.")
                kind, data = entry["type"], entry["data"]
                if kind not in {"job", "event", "guidance"} or not isinstance(data, dict):
                    raise HistoryError("Solver history record type is invalid.")
                counts[kind] += 1
                if sum(counts.values()) > MAX_RECORDS:
                    raise HistoryError("Too many solver history records.")
                yield kind, data
    except (zipfile.BadZipFile, RuntimeError, EOFError, NotImplementedError) as exc:
        raise HistoryError("Solver history ZIP data could not be read.") from exc
    if (size != descriptor["size"] or digest.hexdigest() != descriptor["sha256"]
            or any(counts[kind] != descriptor[f"{kind}_count"] for kind in ("job", "event", "guidance"))):
        raise HistoryError("Solver history checksum or record count does not match.")


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID.fullmatch(value))


def _time(value: Any) -> bool:
    return value is None or (isinstance(value, (int, float)) and not isinstance(value, bool)
                             and math.isfinite(value) and value >= 0)


def inspect_history(bundle: zipfile.ZipFile, descriptor: dict[str, Any],
                    challenge_ids: set[str]) -> tuple[dict[str, str], dict[str, str], list[dict[str, Any]]]:
    """Verify every payload byte and reference before importing any history."""
    jobs: dict[str, str] = {}
    guidance_ids: dict[str, str] = {}
    job_rows: list[dict[str, Any]] = []
    event_sequences: dict[str, int] = {}
    for kind, data in _read(bundle, descriptor):
        if kind == "job":
            if (set(data) != set(JOB_FIELDS) or not _identifier(data.get("id"))
                    or data["id"] in jobs or data.get("challenge_id") not in challenge_ids
                    or data.get("provider") not in {"codex", "claude"}
                    or data.get("job_mode") not in {"solve", "writeup_refine"}
                    or data.get("status") not in _OPEN | _TERMINAL
                    or data.get("auth_kind") not in {"oauth", "api_key"}
                    or data.get("continuation_mode") not in {"fresh", "checkpoint", "workspace", "session"}
                    or data.get("ultra_escalation_mode") not in {"off", "ask", "auto"}
                    or data.get("writeup_locale") not in {"ko", "en"}
                    or not all(isinstance(data.get(field), str) for field in (
                        "account_label", "model", "reasoning_effort", "codex_version",
                        "writeup_instruction", "remote_mode"
                    ))
                    or any(data.get(field) not in (0, 1) for field in (
                        "ultra_auto_attempted", "ultracode", "max_reasoning_available",
                        "continuation_confirmed"
                    ))
                    or isinstance(data.get("last_event_sequence"), bool)
                    or not isinstance(data.get("last_event_sequence"), int)
                    or data["last_event_sequence"] < 0
                    or data.get("created_at") is None or data.get("updated_at") is None
                    or not all(_time(data.get(field)) for field in (
                        "created_at", "claimed_at", "staged_at", "running_at",
                        "first_activity_at", "flag_at", "writeup_at", "updated_at",
                        "released_at", "flag_rejected_at"
                    ))):
                raise HistoryError("Solver job history is invalid or orphaned.")
            for field in ("agents_json", "context_usage_json"):
                try:
                    parsed = json.loads(data[field])
                except (TypeError, ValueError) as exc:
                    raise HistoryError("Solver agent or context history is invalid.") from exc
                if not isinstance(parsed, list if field == "agents_json" else dict):
                    raise HistoryError("Solver agent or context history has the wrong shape.")
            jobs[data["id"]] = uuid.uuid4().hex
            job_rows.append(data)
        elif kind == "event":
            if (set(data) != {"job_id", "sequence", "kind", "event_json", "created_at"}
                    or data.get("job_id") not in jobs
                    or isinstance(data.get("sequence"), bool)
                    or not isinstance(data.get("sequence"), int)
                    or data["sequence"] <= event_sequences.get(data["job_id"], 0)
                    or not isinstance(data.get("kind"), str) or not _time(data.get("created_at"))):
                raise HistoryError("Solver event history is invalid or out of order.")
            try:
                payload = json.loads(data["event_json"])
            except (TypeError, ValueError) as exc:
                raise HistoryError("Solver event payload is invalid.") from exc
            if (not isinstance(payload, dict) or payload.get("job_id") != data["job_id"]
                    or payload.get("sequence") != data["sequence"]
                    or payload.get("kind") != data["kind"]):
                raise HistoryError("Solver event payload does not match its record.")
            event_sequences[data["job_id"]] = data["sequence"]
        else:
            if (set(data) != set(GUIDANCE_FIELDS) or not _identifier(data.get("id"))
                    or data["id"] in guidance_ids or data.get("job_id") not in jobs
                    or not isinstance(data.get("message"), str)
                    or data.get("requested_delivery") not in {"same_turn", "next_turn"}
                    or data.get("status") not in {"queued", "staged", "delivered", "rejected"}
                    or data.get("provider_delivery") not in {None, "same_turn", "next_turn"}
                    or data.get("created_at") is None
                    or not all(_time(data.get(field)) for field in ("created_at", "staged_at", "delivered_at"))):
                raise HistoryError("Solver guidance history is invalid or orphaned.")
            guidance_ids[data["id"]] = uuid.uuid4().hex
    if any(row["last_event_sequence"] < event_sequences.get(row["id"], 0) for row in job_rows):
        raise HistoryError("Solver event cursor is behind its exported events.")
    return jobs, guidance_ids, job_rows


def import_history(db: sqlite3.Connection, bundle: zipfile.ZipFile,
                   descriptor: dict[str, Any] | None, owner: str, workspace_id: str,
                   challenge_ids: dict[str, str]) -> int:
    if descriptor is None:
        return 0  # v1 bundles have no solver log section.
    validate_descriptor(bundle, descriptor)
    jobs, guidance_ids, rows = inspect_history(bundle, descriptor, set(challenge_ids))
    if not rows:
        return 0
    columns = {row[1] for row in db.execute("PRAGMA table_info(solver_jobs)")}
    if "imported_historical" not in columns:
        raise HistoryError("Solver history support is not initialized on this installation.")
    for original in rows:
        data = dict(original)
        old_id = data["id"]
        data.update(
            id=jobs[old_id], owner_user_id=owner, workspace_id=workspace_id,
            challenge_id=challenge_ids[data["challenge_id"]],
            account_id="history_" + jobs[old_id], imported_historical=1,
            cancel_requested=0, released_ingested=1, flag_hooked=1,
            writeup_hooked=1, worker_instance_id=None, solver_artifact_json=None,
            retry_checkpoint_json=None,
        )
        was_open = data["status"] in _OPEN
        if was_open:
            data["status"] = "cancelled"
            data["released_at"] = data["released_at"] or data["updated_at"]
        for field in ("ultra_source_job_id", "continuation_source_job_id", "source_solver_job_id"):
            data[field] = jobs.get(data[field])
        if original["continuation_source_job_id"] not in jobs:
            data["continuation_mode"] = "fresh"
            data["continuation_confirmed"] = 0
        data["ultra_escalation_mode"] = "off"
        data["ultra_auto_attempted"] = 1
        names = list(data)
        db.execute(
            f"INSERT INTO solver_jobs({','.join(names)}) VALUES({','.join('?' for _ in names)})",
            tuple(data[name] for name in names),
        )
    for kind, data in _read(bundle, descriptor):
        if kind == "event":
            payload = json.loads(data["event_json"])
            payload["job_id"] = jobs[data["job_id"]]
            if isinstance(payload.get("guidance_id"), str):
                payload["guidance_id"] = guidance_ids.get(payload["guidance_id"], payload["guidance_id"])
            db.execute(
                "INSERT INTO solver_job_events(job_id,sequence,kind,event_json,created_at) VALUES(?,?,?,?,?)",
                (jobs[data["job_id"]], data["sequence"], data["kind"],
                 json.dumps(payload, ensure_ascii=False, separators=(",", ":")), data["created_at"]),
            )
        elif kind == "guidance":
            status = data["status"] if data["status"] in {"delivered", "rejected"} else "rejected"
            db.execute(
                """INSERT INTO solver_job_guidance(
                   id,job_id,owner_user_id,message,requested_delivery,status,
                   provider_delivery,error_code,created_at,staged_at,delivered_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (guidance_ids[data["id"]], jobs[data["job_id"]], owner,
                 data["message"], data["requested_delivery"], status,
                 data["provider_delivery"],
                 data["error_code"] if status == data["status"] else "imported_history",
                 data["created_at"], data["staged_at"], data["delivered_at"]),
            )
    return len(jobs)
