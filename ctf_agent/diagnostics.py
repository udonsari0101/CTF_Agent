"""Bounded, redacted diagnostic exports for an installation administrator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable
from zipfile import ZIP_DEFLATED, ZipFile


MAX_EVENTS = 100_000
MAX_JOBS = 10_000
_CREDENTIAL = re.compile(
    r"(?i)(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|ctfd_[A-Za-z0-9_-]{12,}"
    r"|Bearer\s+[^\s,;]+"
    r"|(?:\\?[\"'])?(?:authorization|cookie|api[_-]?key|token|password|secret)"
    r"(?:\\?[\"'])?\s*[:=]\s*(?:\\?[\"'])?[^\s,;}\]\"']+)"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_OMIT_FIELDS = {"flag", "writeup_markdown", "private_notes", "message", "token", "password", "cookie", "authorization", "api_key", "secret"}


def _scrub(value: str) -> str:
    return _CREDENTIAL.sub("[redacted credential]", _PRIVATE_KEY.sub("[redacted private key]", value))


def _runtime_info(log_dir: Path) -> dict:
    try:
        disk = shutil.disk_usage(log_dir)
        storage = {"free_bytes": disk.free, "total_bytes": disk.total}
    except OSError:
        storage = {"error": "unavailable"}
    return {
        "release_version": os.environ.get("CTF_RELEASE_VERSION") or "unknown",
        "storage": storage,
    }


def _safe_event(raw: str) -> dict:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {"kind": "unreadable_event"}
    if not isinstance(value, dict):
        return {"kind": "unreadable_event"}
    result = {}
    for key, item in value.items():
        if key in _OMIT_FIELDS or any(part in key.lower() for part in ("credential", "auth_json")):
            continue
        if isinstance(item, str):
            result[key] = _scrub(item[:4000])
        elif isinstance(item, (int, float, bool)) or item is None:
            result[key] = item
        elif key == "error" and isinstance(item, dict):
            result[key] = {"code": item.get("code"), "category": item.get("category"),
                           "stage": item.get("stage")}
    if value.get("kind") == "flag":
        flag = value.get("flag")
        result["flag_sha256"] = hashlib.sha256(flag.encode()).hexdigest() if isinstance(flag, str) else None
    if value.get("kind") == "writeup":
        markdown = value.get("writeup_markdown")
        result["writeup_bytes"] = len(markdown.encode()) if isinstance(markdown, str) else 0
    return result


def _where(hours: int, workspace_id: str | None, challenge_id: str | None,
           *, iso_time: bool = False) -> tuple[str, list]:
    terms = ["created_at>=?"]
    cutoff = time.time() - hours * 3600
    values: list = [datetime.fromtimestamp(cutoff, timezone.utc).isoformat() if iso_time else cutoff]
    if workspace_id:
        terms.append("workspace_id=?")
        values.append(workspace_id)
    if challenge_id:
        terms.append("challenge_id=?")
        values.append(challenge_id)
    return " AND ".join(terms), values


def preview(database: Callable, log_dir: Path, *, hours: int,
            workspace_id: str | None = None, challenge_id: str | None = None) -> dict:
    where, values = _where(hours, workspace_id, challenge_id)
    ctfd_where, ctfd_values = _where(hours, workspace_id, challenge_id, iso_time=True)
    with database() as db:
        job_count = db.execute(f"SELECT COUNT(*) FROM solver_jobs WHERE {where}", values).fetchone()[0]
        event_count, event_bytes = db.execute(
            f"""SELECT COUNT(*),COALESCE(SUM(LENGTH(e.event_json)),0)
                FROM solver_job_events e JOIN solver_jobs j ON j.id=e.job_id
                WHERE j.{where.replace(' AND ', ' AND j.').replace('created_at', 'created_at')}""",
            values,
        ).fetchone()
        submit_count = db.execute(
            f"SELECT COUNT(*) FROM ctfd_submit_jobs WHERE {ctfd_where}", ctfd_values
        ).fetchone()[0]
        import_count = db.execute(
            "SELECT COUNT(*) FROM ctfd_jobs WHERE created_at>=?"
            + (" AND workspace_id=?" if workspace_id else "")
            + (" AND target_challenge_id=?" if challenge_id else ""),
            [ctfd_values[0], *([workspace_id] if workspace_id else []),
             *([challenge_id] if challenge_id else [])],
        ).fetchone()[0]
    log_bytes = 0
    if not workspace_id and not challenge_id:
        log_bytes = sum(
            path.stat().st_size for path in (log_dir / f"web.log{suffix}" for suffix in ("", ".1", ".2", ".3"))
            if not path.is_symlink() and path.is_file()
        )
    return {
        "solver_jobs": job_count, "solver_events": event_count,
        "ctfd_submissions": submit_count, "ctfd_imports": import_count,
        "estimated_uncompressed_bytes": event_bytes + log_bytes + job_count * 512,
        "event_limit": MAX_EVENTS, "job_limit": MAX_JOBS,
        "truncated": event_count > MAX_EVENTS or job_count > MAX_JOBS,
    }


def build_archive(database: Callable, log_dir: Path, *, hours: int,
                  workspace_id: str | None = None, challenge_id: str | None = None) -> BinaryIO:
    """Create a seekable ZIP; callers own and must close the spooled file."""
    output = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
    try:
        summary = preview(database, log_dir, hours=hours, workspace_id=workspace_id,
                          challenge_id=challenge_id)
        where, values = _where(hours, workspace_id, challenge_id)
        ctfd_where, ctfd_values = _where(hours, workspace_id, challenge_id, iso_time=True)
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            with database() as db:
                jobs = [dict(row) for row in db.execute(
                    f"""SELECT id,workspace_id,challenge_id,provider,model,reasoning_effort,
                               status,created_at,claimed_at,running_at,first_activity_at,
                               flag_at,writeup_at,released_at,error_json,flag_rejected_at
                        FROM solver_jobs WHERE {where}
                        ORDER BY created_at DESC LIMIT ?""",
                    [*values, MAX_JOBS],
                )]
                for job in jobs:
                    try:
                        error = json.loads(job.pop("error_json") or "{}")
                    except ValueError:
                        error = {}
                    job["error_code"] = error.get("code") if isinstance(error, dict) else None
                archive.writestr("solver-jobs.json", json.dumps(jobs, ensure_ascii=False))

                with archive.open("solver-events.jsonl", "w") as stream:
                    cursor = db.execute(
                        f"""SELECT e.event_json FROM solver_job_events e
                             JOIN solver_jobs j ON j.id=e.job_id
                             WHERE j.{where.replace(' AND ', ' AND j.')}
                             ORDER BY e.created_at DESC LIMIT ?""",
                        [*values, MAX_EVENTS],
                    )
                    for (raw,) in cursor:
                        stream.write((json.dumps(_safe_event(raw), ensure_ascii=False) + "\n").encode())

                submit_rows = [dict(row) for row in db.execute(
                    f"""SELECT id,workspace_id,challenge_id,status,attempts,result_code,
                               created_at,updated_at,completed_at,source_solver_job_id
                        FROM ctfd_submit_jobs WHERE {ctfd_where} ORDER BY created_at DESC LIMIT ?""",
                    [*ctfd_values, MAX_JOBS],
                )]
                archive.writestr("ctfd-submissions.json", json.dumps(submit_rows, ensure_ascii=False))

                import_where = "created_at>=?" + (" AND workspace_id=?" if workspace_id else "") + (
                    " AND target_challenge_id=?" if challenge_id else ""
                )
                import_values = [ctfd_values[0], *([workspace_id] if workspace_id else []),
                                 *([challenge_id] if challenge_id else [])]
                import_rows = [dict(row) for row in db.execute(
                    f"""SELECT id,workspace_id,status,mode,target_challenge_id,imported,
                               skipped,attachments,downloaded_bytes,total_bytes,created_at,updated_at
                        FROM ctfd_jobs WHERE {import_where} ORDER BY created_at DESC LIMIT ?""",
                    [*import_values, MAX_JOBS],
                )]
                archive.writestr("ctfd-imports.json", json.dumps(import_rows, ensure_ascii=False))

            if not workspace_id and not challenge_id:
                for name in ("web.log", "web.log.1", "web.log.2", "web.log.3"):
                    path = log_dir / name
                    if path.is_symlink() or not path.is_file():
                        continue
                    with path.open("r", encoding="utf-8", errors="replace") as source, archive.open(
                        f"logs/{name}", "w"
                    ) as target:
                        for line in source:
                            target.write((_scrub(line)[:16_384] + "\n").encode())
            archive.writestr("about.json", json.dumps({
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "hours": hours, "workspace_id": workspace_id, "challenge_id": challenge_id,
                "summary": summary, "runtime": _runtime_info(log_dir), "redacted": True,
            }, ensure_ascii=False))
        output.seek(0)
        return output
    except BaseException:
        output.close()
        raise
