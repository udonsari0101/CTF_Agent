"""Small, cached Linux resource snapshot for the workspace header."""

from __future__ import annotations

import threading
import time
from pathlib import Path


class ResourceMonitor:
    """Report aggregate system CPU and memory without enumerating processes."""

    def __init__(
        self,
        *,
        proc_stat: Path = Path("/proc/stat"),
        meminfo: Path = Path("/proc/meminfo"),
        cache_seconds: float = 2.0,
        monotonic=time.monotonic,
    ):
        self.proc_stat = proc_stat
        self.meminfo = meminfo
        self.cache_seconds = max(0.0, cache_seconds)
        self.monotonic = monotonic
        self._lock = threading.Lock()
        self._previous_cpu = self._read_cpu()
        self._cached: dict | None = None
        self._cached_until = 0.0

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None

    def _read_cpu(self) -> tuple[int, int] | None:
        text = self._read_text(self.proc_stat)
        if not text:
            return None
        first = text.splitlines()[0].split()
        if not first or first[0] != "cpu" or len(first) < 5:
            return None
        try:
            counters = [int(value) for value in first[1:]]
        except ValueError:
            return None
        if any(value < 0 for value in counters):
            return None
        idle = counters[3] + (counters[4] if len(counters) > 4 else 0)
        return sum(counters), idle

    def _read_memory(self) -> tuple[int, int] | None:
        text = self._read_text(self.meminfo)
        if not text:
            return None
        values: dict[str, int] = {}
        for line in text.splitlines():
            key, separator, remainder = line.partition(":")
            if not separator or key not in {"MemTotal", "MemAvailable"}:
                continue
            fields = remainder.split()
            try:
                value = int(fields[0])
            except (IndexError, ValueError):
                continue
            unit = fields[1].lower() if len(fields) > 1 else "b"
            if value < 0 or unit not in {"b", "kb"}:
                continue
            values[key] = value * (1024 if unit == "kb" else 1)
        total = values.get("MemTotal")
        available = values.get("MemAvailable")
        if not total or available is None or available > total:
            return None
        return total - available, total

    def snapshot(self) -> dict:
        with self._lock:
            sampled_at = self.monotonic()
            if self._cached is not None and sampled_at < self._cached_until:
                return dict(self._cached)

            current_cpu = self._read_cpu()
            cpu_percent = None
            if current_cpu is not None and self._previous_cpu is not None:
                total_delta = current_cpu[0] - self._previous_cpu[0]
                idle_delta = current_cpu[1] - self._previous_cpu[1]
                if total_delta > 0 and 0 <= idle_delta <= total_delta:
                    cpu_percent = round(
                        min(100.0, max(0.0, (total_delta - idle_delta) * 100 / total_delta)),
                        1,
                    )
            if current_cpu is not None:
                self._previous_cpu = current_cpu

            memory = self._read_memory()
            memory_used, memory_total = memory if memory is not None else (None, None)
            memory_percent = (
                round(memory_used * 100 / memory_total, 1)
                if memory_used is not None and memory_total
                else None
            )
            result = {
                "available": cpu_percent is not None or memory is not None,
                "scope": "system",
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "memory_used_bytes": memory_used,
                "memory_total_bytes": memory_total,
            }
            self._cached = result
            self._cached_until = sampled_at + self.cache_seconds
            return dict(result)


__all__ = ["ResourceMonitor"]
