"""Manage installer control files without weakening the protected data root."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import time


def manage(root: Path, action: str, uid: int, gid: int, token: str = "") -> str:
    if root.is_symlink() or not root.is_dir() or action not in {"reserve", "release"}:
        raise RuntimeError("Invalid installer storage control request")
    drain = root / "deployment-drain"
    if action == "reserve":
        control = root / "update-control"
        if control.is_symlink() or (control.exists() and not control.is_dir()):
            raise RuntimeError("Invalid update-control directory")
        control.mkdir(mode=0o700, exist_ok=True)
        os.chown(control, uid, gid)
        control.chmod(0o700)
        if drain.exists() or drain.is_symlink():
            current = drain.lstat()
            if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                    or current.st_size or current.st_uid != uid
                    or time.time() - current.st_mtime < 7200):
                raise RuntimeError("Another deployment drain is active or invalid")
            drain.unlink()
        fd = os.open(drain, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(fd, uid, gid)
            current = os.fstat(fd)
            return f"{current.st_ino}:{current.st_mtime_ns}"
        finally:
            os.close(fd)
    if not drain.exists() and not drain.is_symlink():
        return ""
    current = drain.lstat()
    if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
            or current.st_size or current.st_uid != uid
            or token != f"{current.st_ino}:{current.st_mtime_ns}"):
        raise RuntimeError("Deployment drain identity changed; it was preserved")
    drain.unlink()
    return ""


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("Expected action, uid, gid and drain token")
    print(manage(Path("/data"), sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))
