"""Bounded, private observation of repeated root shell results during a solve.

No command, output, or stable digest leaves this object. A repeated result is
only a prompt for re-evaluation on the next provider turn, never a stop rule.
"""

from __future__ import annotations

from collections import Counter, deque
import hashlib
import secrets


class SolveRepeatObserver:
    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self._pending: dict[str, bytes] = {}
        self._recent: deque[tuple[bytes, bytes]] = deque(maxlen=6)
        self._hint_pending = False

    def started(self, activity_id: str | None, command: object) -> None:
        if not isinstance(activity_id, str) or not isinstance(command, str):
            return
        data = command.encode("utf-8", errors="replace")
        if not data or len(data) > 64 * 1024:
            return
        if len(self._pending) >= 128:
            self._pending.clear()
        self._pending[activity_id] = self._digest(data)

    def completed(self, activity_id: str | None, output: object, exit_code: object) -> None:
        command = self._pending.pop(activity_id, None) if isinstance(activity_id, str) else None
        if command is None or not isinstance(output, str):
            return
        data = output.encode("utf-8", errors="replace")
        if not data or len(data) > 1024 * 1024:
            return
        result = self._digest(data + b"\0" + str(exit_code if type(exit_code) is int else "unknown").encode())
        signature = (command, result)
        self._recent.append(signature)
        if Counter(self._recent)[signature] >= 3:
            self._hint_pending = True

    def take_hint(self) -> bool:
        pending = self._hint_pending
        self._hint_pending = False
        return pending

    def _digest(self, value: bytes) -> bytes:
        return hashlib.blake2s(value, key=self._key, digest_size=16).digest()
