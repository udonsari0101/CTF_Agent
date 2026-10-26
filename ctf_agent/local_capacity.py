"""Resource-aware solver concurrency for local Docker Desktop installs."""

from __future__ import annotations

import math
import os
from pathlib import Path


GIB = 1024**3


def _text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _cpuset_count(value: str | None) -> int | None:
    if not value:
        return None
    cpus: set[int] = set()
    try:
        for item in value.split(","):
            bounds = item.strip().split("-", 1)
            start = int(bounds[0])
            end = int(bounds[-1])
            if start < 0 or end < start:
                return None
            cpus.update(range(start, end + 1))
    except ValueError:
        return None
    return len(cpus) or None


def _cpu_limit(cgroup: Path, fallback: int) -> int:
    limits = [max(1, fallback)]
    limits.extend(
        value
        for value in (
            _cpuset_count(_text(cgroup / "cpuset.cpus.effective")),
            _cpuset_count(_text(cgroup / "cpuset" / "cpuset.cpus")),
        )
        if value is not None
    )
    cpu_max = _text(cgroup / "cpu.max")
    if cpu_max:
        fields = cpu_max.split()
        if len(fields) == 2 and fields[0] != "max":
            try:
                quota, period = int(fields[0]), int(fields[1])
                if quota > 0 and period > 0:
                    limits.append(max(1, math.ceil(quota / period)))
            except ValueError:
                pass
    else:
        quota = _text(cgroup / "cpu" / "cpu.cfs_quota_us")
        period = _text(cgroup / "cpu" / "cpu.cfs_period_us")
        try:
            if quota is not None and period is not None and int(quota) > 0 and int(period) > 0:
                limits.append(max(1, math.ceil(int(quota) / int(period))))
        except ValueError:
            pass
    return min(limits)


def _host_available_memory(meminfo: Path) -> int | None:
    value = _text(meminfo)
    if not value:
        return None
    for line in value.splitlines():
        if line.startswith("MemAvailable:"):
            try:
                return int(line.split()[1]) * 1024
            except (IndexError, ValueError):
                return None
    return None


def _available_memory(cgroup: Path, meminfo: Path) -> int | None:
    candidates = []
    host = _host_available_memory(meminfo)
    if host is not None:
        candidates.append(host)
    maximum = _text(cgroup / "memory.max")
    current = _text(cgroup / "memory.current")
    if maximum and maximum != "max" and current:
        try:
            candidates.append(max(0, int(maximum) - int(current)))
        except ValueError:
            pass
    else:
        maximum = _text(cgroup / "memory" / "memory.limit_in_bytes")
        current = _text(cgroup / "memory" / "memory.usage_in_bytes")
        try:
            if maximum and current and 0 < int(maximum) < (1 << 60):
                candidates.append(max(0, int(maximum) - int(current)))
        except ValueError:
            pass
    return min(candidates) if candidates else None


def recommended_solver_concurrency(
    *,
    cgroup: Path = Path("/sys/fs/cgroup"),
    meminfo: Path = Path("/proc/meminfo"),
    logical_cpus: int | None = None,
    override: str | None = None,
) -> int:
    """Choose a conservative worker count from effective cgroup limits.

    One solver is budgeted two logical CPUs and 6 GiB, after reserving 2 GiB
    for Docker Desktop, the web service, and SQLite. An explicit positive
    override wins and is not subject to an arbitrary software ceiling.
    """

    selected = override if override is not None else os.environ.get("CTF_SOLVER_MAX_CONCURRENT")
    if selected not in (None, ""):
        try:
            value = int(selected)
        except ValueError as exc:
            raise ValueError("CTF_SOLVER_MAX_CONCURRENT must be an integer") from exc
        if value < 1:
            raise ValueError("local CTF_SOLVER_MAX_CONCURRENT must be positive")
        return value
    cpus = _cpu_limit(cgroup, logical_cpus or os.cpu_count() or 1)
    cpu_slots = max(1, cpus // 2)
    available = _available_memory(cgroup, meminfo)
    memory_slots = cpu_slots
    if available is not None:
        memory_slots = max(1, (max(0, available - 2 * GIB)) // (6 * GIB))
    return max(1, min(cpu_slots, memory_slots))


__all__ = ["GIB", "recommended_solver_concurrency"]
