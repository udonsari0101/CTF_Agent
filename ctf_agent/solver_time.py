"""Elapsed-time origin for a solve continued across durable jobs."""

from __future__ import annotations

import json
import math
from typing import Any, Mapping


def _sources(db: Any, job: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return validated ancestors, nearest first, without crossing owners."""
    if job["job_mode"] != "solve" or not job["continuation_source_job_id"]:
        return []
    current = job
    sources = []
    seen = {job["id"]}
    for _ in range(128):
        source_id = current["continuation_source_job_id"]
        if not source_id or source_id in seen:
            break
        source = db.execute(
            """SELECT id,job_mode,created_at,continuation_source_job_id,
                      flag,flag_rejected_at
                 FROM solver_jobs
                WHERE id=? AND owner_user_id=? AND workspace_id=?
                  AND challenge_id=? AND job_mode='solve'""",
            (
                source_id, job["owner_user_id"], job["workspace_id"],
                job["challenge_id"],
            ),
        ).fetchone()
        if source is None:
            break
        sources.append(source)
        seen.add(source["id"])
        current = source
    return sources


def continuation_start(db: Any, job: Mapping[str, Any]) -> tuple[float, bool] | None:
    """Return the first solve's start, scoped to the same owner and challenge.

    A new solve has no inherited clock. A resumed solve keeps the earliest
    ancestor's running event, even if it changed provider or model. Older jobs
    without that event fall back to creation time and are labeled accordingly.
    """

    sources = _sources(db, job)
    if not sources:
        return None
    earliest = sources[-1]
    for event in db.execute(
        """SELECT event_json,created_at FROM solver_job_events
             WHERE job_id=? AND kind='status' ORDER BY sequence""",
        (earliest["id"],),
    ):
        try:
            payload = json.loads(event["event_json"])
        except (TypeError, ValueError):
            continue
        started_at = event["created_at"]
        if (
            isinstance(payload, dict) and payload.get("status") == "running"
            and isinstance(started_at, (int, float))
            and math.isfinite(started_at) and started_at > 0
        ):
            return float(started_at), True
    created_at = earliest["created_at"]
    if isinstance(created_at, (int, float)) and math.isfinite(created_at) and created_at > 0:
        return float(created_at), False
    return None


def continuation_flag_time(db: Any, job: Mapping[str, Any]) -> float | None:
    """Find the first accepted flag in the continued solve's ancestry."""

    flag = job["flag"]
    if not isinstance(flag, str) or not flag:
        return None
    for source in reversed(_sources(db, job)):
        if source["flag"] != flag or source["flag_rejected_at"] is not None:
            continue
        for event in db.execute(
            """SELECT event_json,created_at FROM solver_job_events
                 WHERE job_id=? AND kind='flag' ORDER BY sequence""",
            (source["id"],),
        ):
            try:
                payload = json.loads(event["event_json"])
            except (TypeError, ValueError):
                continue
            found_at = event["created_at"]
            if (
                isinstance(payload, dict) and payload.get("flag") == flag
                and isinstance(found_at, (int, float))
                and math.isfinite(found_at) and found_at > 0
            ):
                return float(found_at)
    return None
