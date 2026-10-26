"""Crash-safe shared accounting for writes to the data volume.

The SQLite rows reserve bytes that have not been written yet.  The lock file is
on the data volume itself, so separate application processes which share that
volume serialize the disk check and reservation update.  A reserved write is
made durable before its reservation is reduced; a crash can therefore only
leave an overly conservative reservation, never an unaccounted durable write.
"""

from __future__ import annotations

import os
import shutil
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterable, Mapping

try:  # Linux containers use flock; the fallback keeps Windows test threads safe.
    import fcntl
except ImportError:  # pragma: no cover - exercised by the Windows test runner
    fcntl = None


DEFAULT_MIN_FREE_BYTES = 1024 * 1024 * 1024
MAX_SQLITE_INTEGER = 2**63 - 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_reservations (
    reservation_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    challenge_id TEXT,
    remaining_bytes INTEGER NOT NULL CHECK(remaining_bytes >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_storage_reservation_scope
ON storage_reservations(kind, owner_user_id, workspace_id, challenge_id);
"""


class StorageBudgetError(RuntimeError):
    """A safe, user-displayable storage accounting error."""


_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


def _process_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.resolve()))
    with _LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(key, threading.RLock())


def _configured_floor(settings=None) -> int:
    configured = getattr(settings, "storage_min_free_bytes", None)
    raw = configured if configured is not None else os.environ.get(
        "CTF_STORAGE_MIN_FREE_BYTES", str(DEFAULT_MIN_FREE_BYTES)
    )
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("CTF_STORAGE_MIN_FREE_BYTES must be a non-negative integer.") from exc
    if value < 0 or value > MAX_SQLITE_INTEGER:
        raise RuntimeError("CTF_STORAGE_MIN_FREE_BYTES must be a non-negative 64-bit integer.")
    return value


class StorageBudget:
    """Coordinates reservations and durable writes on one shared data volume."""

    def __init__(self, data_dir: Path, connect: Callable, *, minimum_free_bytes: int | None = None):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.minimum_free_bytes = (
            _configured_floor()
            if minimum_free_bytes is None
            else int(minimum_free_bytes)
        )
        if not 0 <= self.minimum_free_bytes <= MAX_SQLITE_INTEGER:
            raise ValueError("minimum_free_bytes must be a non-negative 64-bit integer")
        self.connect = connect
        self.lock_path = self.data_dir / ".storage-budget.lock"
        self._thread_lock = _process_lock(self.lock_path)
        with self.exclusive():
            connection = self.connect()
            try:
                connection.executescript(SCHEMA)
                connection.commit()
            finally:
                connection.close()

    @contextmanager
    def exclusive(self):
        """Hold the process lock and Linux cross-process flock for this volume."""
        with self._thread_lock:
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.lock_path, flags, 0o600)
            except OSError as exc:
                raise StorageBudgetError("저장 공간 잠금 파일을 열 수 없습니다.") from exc
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise StorageBudgetError("저장 공간 잠금 경로가 올바르지 않습니다.")
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(descriptor)

    @contextmanager
    def _transaction(self):
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _free(self) -> int:
        try:
            return int(shutil.disk_usage(self.data_dir).free)
        except OSError as exc:
            raise StorageBudgetError("저장 공간 상태를 확인할 수 없습니다.") from exc

    @staticmethod
    def _validate(key: str, kind: str, owner: str, workspace: str,
                  challenge: str | None, remaining: int) -> None:
        values = (key, kind, owner, workspace)
        if any(not isinstance(value, str) or not value or len(value) > 256 for value in values):
            raise ValueError("invalid storage reservation scope")
        if challenge is not None and (not isinstance(challenge, str) or not challenge or len(challenge) > 256):
            raise ValueError("invalid storage reservation challenge")
        if type(remaining) is not int or not 0 <= remaining <= MAX_SQLITE_INTEGER:
            raise ValueError("invalid storage reservation size")

    @staticmethod
    def _total(connection) -> int:
        # Python's arbitrary-precision sum avoids SQLite SUM integer overflow.
        return sum(int(row[0]) for row in connection.execute(
            "SELECT remaining_bytes FROM storage_reservations"
        ))

    @staticmethod
    def _matching(row, kind, owner, workspace, challenge) -> bool:
        return (
            row["kind"] == kind
            and row["owner_user_id"] == owner
            and row["workspace_id"] == workspace
            and row["challenge_id"] == challenge
        )

    def reserve(self, key: str, kind: str, owner: str, workspace: str,
                challenge: str | None, remaining: int,
                db_update: Callable | None = None,
                prepare: Callable | None = None) -> None:
        """Atomically set a reservation, optionally with caller metadata changes."""
        self._validate(key, kind, owner, workspace, challenge, remaining)
        with self.exclusive(), self._transaction() as connection:
            current = connection.execute(
                "SELECT * FROM storage_reservations WHERE reservation_key=?", (key,)
            ).fetchone()
            if current and not self._matching(current, kind, owner, workspace, challenge):
                raise StorageBudgetError("저장 공간 예약 범위가 일치하지 않습니다.")
            total = self._total(connection)
            previous = int(current["remaining_bytes"]) if current else 0
            projected = total - previous + remaining
            if self._free() - projected < self.minimum_free_bytes:
                raise StorageBudgetError("저장 공간이 부족합니다. 공간을 확보한 뒤 다시 시도해 주세요.")
            if prepare is not None:
                prepare()
            now = int(time.time())
            if remaining:
                connection.execute(
                    """INSERT INTO storage_reservations
                       (reservation_key,kind,owner_user_id,workspace_id,challenge_id,
                        remaining_bytes,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?)
                       ON CONFLICT(reservation_key) DO UPDATE SET
                        remaining_bytes=excluded.remaining_bytes,updated_at=excluded.updated_at""",
                    (key, kind, owner, workspace, challenge, remaining,
                     int(current["created_at"]) if current else now, now),
                )
            else:
                connection.execute(
                    "DELETE FROM storage_reservations WHERE reservation_key=?", (key,)
                )
            if db_update:
                db_update(connection)

    def commit_reserved_write(self, key: str, amount: int, writer: Callable[[], None], *,
                              precheck: Callable | None = None,
                              db_update: Callable | None = None) -> bool:
        """Durably write reserved bytes, then atomically consume their reservation.

        ``writer`` must return only after those bytes are durable (normally after
        flush + fsync). ``precheck`` may return ``False`` for an already committed
        idempotent operation. Caller metadata in ``db_update`` commits in the same
        SQLite transaction as the reservation decrement.
        """
        if type(amount) is not int or amount <= 0 or amount > MAX_SQLITE_INTEGER:
            raise ValueError("invalid reserved write size")
        with self.exclusive():
            connection = self.connect()
            try:
                row = connection.execute(
                    "SELECT remaining_bytes FROM storage_reservations WHERE reservation_key=?",
                    (key,),
                ).fetchone()
                if precheck is not None and precheck(connection) is False:
                    return False
                if not row or int(row[0]) < amount:
                    raise StorageBudgetError("저장 공간 예약이 없거나 부족합니다. 업로드를 다시 시작해 주세요.")
                total = self._total(connection)
            finally:
                connection.close()
            # The current reservation already includes amount.  This condition
            # guarantees that physical free space remains above the floor after
            # this write and every other outstanding reservation is consumed.
            if self._free() < self.minimum_free_bytes + total:
                raise StorageBudgetError("저장 공간이 부족합니다. 공간을 확보한 뒤 이어서 시도해 주세요.")
            writer()
            with self._transaction() as connection:
                row = connection.execute(
                    "SELECT remaining_bytes FROM storage_reservations WHERE reservation_key=?",
                    (key,),
                ).fetchone()
                if not row or int(row[0]) < amount:
                    raise StorageBudgetError("저장 공간 예약 상태가 변경되었습니다.")
                if precheck is not None and precheck(connection) is False:
                    raise StorageBudgetError("저장 작업 상태가 쓰기 중 변경되었습니다.")
                if db_update is not None:
                    db_update(connection)
                remaining = int(row[0]) - amount
                if remaining:
                    connection.execute(
                        "UPDATE storage_reservations SET remaining_bytes=?,updated_at=? WHERE reservation_key=?",
                        (remaining, int(time.time()), key),
                    )
                else:
                    connection.execute(
                        "DELETE FROM storage_reservations WHERE reservation_key=?", (key,)
                    )
            return True

    def write_unreserved(self, amount: int, writer: Callable[[], None]) -> None:
        """Write one unknown-length chunk while holding the volume-wide lock."""
        if type(amount) is not int or amount <= 0 or amount > MAX_SQLITE_INTEGER:
            raise ValueError("invalid unreserved write size")
        with self.exclusive():
            connection = self.connect()
            try:
                total = self._total(connection)
            finally:
                connection.close()
            if self._free() - amount - total < self.minimum_free_bytes:
                raise StorageBudgetError("저장 공간이 부족합니다. 공간을 확보한 뒤 이어서 시도해 주세요.")
            writer()

    def release(self, key: str, db_update: Callable | None = None,
                cleanup: Callable | None = None,
                precheck: Callable | None = None) -> bool:
        with self.exclusive():
            if precheck is not None:
                connection = self.connect()
                try:
                    if precheck(connection) is False:
                        return False
                finally:
                    connection.close()
            if cleanup is not None:
                cleanup()
            with self._transaction() as connection:
                if precheck is not None and precheck(connection) is False:
                    raise StorageBudgetError("저장 정리 상태가 처리 중 변경되었습니다.")
                connection.execute("DELETE FROM storage_reservations WHERE reservation_key=?", (key,))
                if db_update is not None:
                    db_update(connection)
            return True

    def release_many(self, keys: Iterable[str]) -> None:
        unique = tuple(dict.fromkeys(key for key in keys if isinstance(key, str) and key))
        if not unique:
            return
        with self.exclusive(), self._transaction() as connection:
            connection.executemany(
                "DELETE FROM storage_reservations WHERE reservation_key=?",
                ((key,) for key in unique),
            )

    def release_scope(self, kind: str, workspace: str, challenge: str | None = None) -> None:
        with self.exclusive(), self._transaction() as connection:
            if challenge is None:
                connection.execute(
                    "DELETE FROM storage_reservations WHERE kind=? AND workspace_id=?",
                    (kind, workspace),
                )
            else:
                connection.execute(
                    "DELETE FROM storage_reservations WHERE kind=? AND workspace_id=? AND challenge_id=?",
                    (kind, workspace, challenge),
                )

    def reconcile_kind(self, kind: str,
                       expected: Mapping[str, tuple[str, str, str | None, int]] | Callable) -> None:
        """Replace one kind's rows with conservative state rebuilt from durable metadata.

        Recovery does not reject overcommit: keeping the promises blocks new
        allocations and lets subsequent writes re-check the physical floor.
        """
        with self.exclusive():
            current_expected = expected() if callable(expected) else expected
            checked = {}
            for key, (owner, workspace, challenge, remaining) in current_expected.items():
                self._validate(key, kind, owner, workspace, challenge, remaining)
                if remaining:
                    checked[key] = (owner, workspace, challenge, remaining)
            with self._transaction() as connection:
                existing = {
                    row[0] for row in connection.execute(
                        "SELECT reservation_key FROM storage_reservations WHERE kind=?", (kind,)
                    )
                }
                connection.executemany(
                    "DELETE FROM storage_reservations WHERE reservation_key=?",
                    ((key,) for key in existing - checked.keys()),
                )
                now = int(time.time())
                for key, (owner, workspace, challenge, remaining) in checked.items():
                    current = connection.execute(
                        "SELECT created_at FROM storage_reservations WHERE reservation_key=?", (key,)
                    ).fetchone()
                    connection.execute(
                        """INSERT INTO storage_reservations
                           (reservation_key,kind,owner_user_id,workspace_id,challenge_id,
                            remaining_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)
                           ON CONFLICT(reservation_key) DO UPDATE SET
                            kind=excluded.kind,owner_user_id=excluded.owner_user_id,
                            workspace_id=excluded.workspace_id,challenge_id=excluded.challenge_id,
                            remaining_bytes=excluded.remaining_bytes,updated_at=excluded.updated_at""",
                        (key, kind, owner, workspace, challenge, remaining,
                         int(current[0]) if current else now, now),
                    )

    def snapshot(self, *, kind: str | None = None) -> list[dict]:
        """Return non-secret accounting rows for diagnostics and tests."""
        connection = self.connect()
        try:
            if kind is None:
                rows = connection.execute(
                    "SELECT * FROM storage_reservations ORDER BY reservation_key"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM storage_reservations WHERE kind=? ORDER BY reservation_key", (kind,)
                ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()


def get_storage_budget(app, settings) -> StorageBudget:
    """Create one coordinator per app and share it between upload/import services."""
    existing = getattr(app.state, "storage_budget", None)
    if existing is not None:
        if existing.data_dir != Path(settings.data_dir).resolve():
            raise RuntimeError("The application data volume changed after storage setup.")
        return existing
    budget = StorageBudget(
        settings.data_dir,
        app.state.connect,
        minimum_free_bytes=_configured_floor(settings),
    )
    app.state.storage_budget = budget
    return budget
