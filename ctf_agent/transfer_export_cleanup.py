"""Lifetime and disconnect-safe cleanup for manual ZIP download exports."""

from __future__ import annotations

import os
import re
import stat
import time
import uuid
from pathlib import Path

from fastapi.responses import FileResponse

from .db import Settings
from .process_lock import ProcessFileLock


EXPORT_TTL_SECONDS = 7 * 24 * 3600
_ZIP = re.compile(r"([0-9a-f]{32})\.zip\Z")
_STAGE = re.compile(r"\.([0-9a-f]{32})\.zip\.[0-9a-f]{32}\.tmp\Z")


class TransferExportResponse(FileResponse):
    """Remove the ZIP even if sending ends through a disconnect/cancellation."""

    def __init__(self, path: Path, lock: ProcessFileLock, **kwargs):
        super().__init__(path, **kwargs)
        self._export_path = path
        self._export_lock = lock

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                self._export_path.unlink(missing_ok=True)
            finally:
                self._export_lock.release()


class TransferExportManager:
    def __init__(self, settings: Settings):
        self.root = Path(settings.data_dir) / "workspaces" / ".transfers" / "exports"
        self.lock_root = Path(settings.config_dir) / ".locks" / "transfer_exports"
        for directory in (self.root, self.lock_root):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not stat.S_ISDIR(directory.lstat().st_mode):
                raise ValueError("Transfer export directory is invalid")

    def _lock(self, identifier: str) -> ProcessFileLock:
        return ProcessFileLock(self.lock_root / f"{identifier}.lock")

    def reserve(self) -> tuple[Path, ProcessFileLock]:
        for _ in range(3):
            identifier = uuid.uuid4().hex
            destination = self.root / f"{identifier}.zip"
            if destination.exists() or destination.is_symlink():
                continue
            lock = self._lock(identifier)
            if lock.try_acquire():
                return destination, lock
        raise RuntimeError("Could not reserve a transfer export path")

    @staticmethod
    def discard(destination: Path, lock: ProcessFileLock) -> None:
        try:
            destination.unlink(missing_ok=True)
        finally:
            lock.release()

    def cleanup_stale(self) -> int:
        """Delete up to 100 old ZIPs/stages, skipping files locked by downloads."""
        threshold = time.time() - EXPORT_TTL_SECONDS
        cleaned = 0
        scanned = 0
        with os.scandir(self.root) as entries:
            for entry in entries:
                scanned += 1
                if scanned > 1000 or cleaned >= 100:
                    break
                match = _ZIP.fullmatch(entry.name) or _STAGE.fullmatch(entry.name)
                if match is None:
                    continue
                path = self.root / entry.name
                try:
                    details = path.lstat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(details.st_mode) or details.st_mtime >= threshold:
                    continue
                lock = self._lock(match.group(1))
                if not lock.try_acquire():
                    continue
                try:
                    try:
                        current = path.lstat()
                    except FileNotFoundError:
                        continue
                    if stat.S_ISREG(current.st_mode) and current.st_mtime < threshold:
                        path.unlink()
                        cleaned += 1
                finally:
                    lock.release()
        return cleaned
