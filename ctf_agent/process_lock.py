"""Small advisory file locks shared by threads and rolling app processes."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import threading
import weakref
from pathlib import Path


_GUARD = threading.Lock()
_LOCAL_LOCKS: weakref.WeakValueDictionary[str, threading.Lock] = weakref.WeakValueDictionary()


def _local_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(str(path.resolve()))
    with _GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.Lock())


class ProcessFileLock:
    """A nonblocking exclusive lock with explicit acquire/release semantics."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._local = _local_lock(self.path)
        self._descriptor: int | None = None

    @property
    def locked(self) -> bool:
        return self._descriptor is not None

    def try_acquire(self) -> bool:
        if self._descriptor is not None:
            return True
        if not self._local.acquire(blocking=False):
            return False
        descriptor = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("lock path is not a regular file")
            if os.name == "posix":
                import fcntl

                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    os.close(descriptor)
                    descriptor = None
                    self._local.release()
                    return False
            else:  # pragma: no cover - behavior is exercised on Windows CI
                import msvcrt

                if info.st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK, 13, 36}:
                        raise
                    os.close(descriptor)
                    descriptor = None
                    self._local.release()
                    return False
            self._descriptor = descriptor
            return True
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            self._local.release()
            raise

    def release(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is None:
            return
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            else:  # pragma: no cover - behavior is exercised on Windows CI
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)
            self._local.release()

    def __enter__(self):
        if not self.try_acquire():
            raise BlockingIOError("lock is already held")
        return self

    def __exit__(self, *_exc) -> None:
        self.release()


def account_lifecycle_lock(accounts_dir: Path, owner_user_id: str) -> ProcessFileLock:
    """Return the shared owner lock used by auth mutations and solver enqueue.

    An owner-scoped lock is intentional: one pending interactive login must
    prevent that user's selected account from being staged by a solver, even
    when another web process serves the enqueue request.  Hashing keeps user
    identifiers out of filesystem diagnostics and produces a fixed safe name.
    """

    if not isinstance(owner_user_id, str) or not owner_user_id:
        raise ValueError("account lifecycle owner is required")
    digest = hashlib.sha256(owner_user_id.encode("utf-8")).hexdigest()
    return ProcessFileLock(Path(accounts_dir) / ".locks" / f"owner-{digest}.lock")
