"""Active solve time across durable continuation jobs."""

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
            """SELECT id,job_mode,status,created_at,updated_at,released_at,
                      continuation_source_job_id,flag,flag_rejected_at
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


def _timestamp(value: Any) -> float | None:
    if (
        isinstance(value, (int, float)) and not isinstance(value, bool)
        and math.isfinite(value) and value > 0
    ):
        return float(value)
    return None


def continuation_elapsed(
    db: Any,
    job: Mapping[str, Any],
    *,
    now: float | None = None,
    stop_at_flag: bool = True,
) -> dict[str, float | bool | None]:
    """Sum execution intervals, omitting every gap between solve attempts.

    ``seconds`` contains closed intervals. The caller may add the time since
    ``running_since`` for a live job. Queued continuations have no open interval,
    so their displayed clock remains fixed until the worker actually starts.
    Event timestamps are coordinator commit times, as are ``released_at`` and
    ``updated_at``; provider event clocks are deliberately not mixed in.
    """

    limit = _timestamp(now)
    chain = [*reversed(_sources(db, job)), job]
    total = 0.0
    includes_queue = False
    accepted_flag = (
        job["flag"] if job["job_mode"] == "solve" and stop_at_flag
        and job["flag_rejected_at"] is None
        and isinstance(job["flag"], str) and job["flag"] else None
    )
    for index, attempt in enumerate(chain):
        current = index == len(chain) - 1
        opened: float | None = None
        saw_running = False
        stopped_at_flag = False
        events = db.execute(
            """SELECT kind,event_json,created_at FROM solver_job_events
                 WHERE job_id=? AND kind IN ('status','flag','released')
                 ORDER BY sequence""",
            (attempt["id"],),
        )
        for event in events:
            at = _timestamp(event["created_at"])
            if at is None or (limit is not None and at > limit):
                continue
            try:
                payload = json.loads(event["event_json"])
            except (TypeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            if event["kind"] == "status":
                if payload.get("status") == "running":
                    saw_running = True
                    if opened is None:
                        opened = at
                elif payload.get("status") in {"interrupted", "awaiting_credential"}:
                    if opened is not None:
                        total += max(0.0, at - opened)
                        opened = None
            elif event["kind"] == "flag" and (
                accepted_flag is not None and payload.get("flag") == accepted_flag
                and attempt["flag"] == accepted_flag
                and attempt["flag_rejected_at"] is None
            ):
                if opened is not None:
                    total += max(0.0, at - opened)
                    opened = None
                elif not saw_running and attempt["status"] == "completed":
                    created = _timestamp(attempt["created_at"])
                    if created is not None:
                        total += max(0.0, at - created)
                        includes_queue = True
                stopped_at_flag = True
                break
            elif event["kind"] == "released":
                if opened is not None:
                    total += max(0.0, at - opened)
                    opened = None
        if stopped_at_flag:
            return {"seconds": min(total, 31_536_000.0), "running_since": None,
                    "includes_queue": includes_queue}
        released = _timestamp(attempt["released_at"])
        if released is not None and (limit is None or released <= limit):
            if opened is not None:
                total += max(0.0, released - opened)
                opened = None
            elif not saw_running and attempt["status"] in {"completed", "failed", "needs_input"}:
                # Older completed rows can predate durable status events. Only
                # these use the historical, explicitly labeled queue fallback.
                created = _timestamp(attempt["created_at"])
                if created is not None:
                    total += max(0.0, released - created)
                    includes_queue = True
        elif opened is not None and limit is not None and released is not None and released > limit:
            # A notification can ask for the clock at its earlier event even
            # though this job has since reached a terminal status.
            if current:
                return {"seconds": min(total, 31_536_000.0),
                        "running_since": opened, "includes_queue": includes_queue}
            total += max(0.0, limit - opened)
            opened = None
        elif opened is not None and (not current or attempt["status"] not in {
            "running", "flag_found", "writing"
        }):
            # An interrupted/requeued job may keep its old running event.
            # Its last durable update is the end of that execution interval.
            updated = _timestamp(attempt["updated_at"])
            if updated is not None:
                total += max(0.0, updated - opened)
            opened = None
        if current and opened is not None:
            return {"seconds": min(total, 31_536_000.0),
                    "running_since": opened, "includes_queue": includes_queue}
    return {"seconds": min(total, 31_536_000.0), "running_since": None,
            "includes_queue": includes_queue}


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
