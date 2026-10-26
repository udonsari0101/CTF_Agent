"""Binary-safe stdio client for the current job's restricted remote relay."""

from __future__ import annotations

import argparse
import os
import socket
import stat
import sys
import threading
from pathlib import Path


SOCKET_NAME = ".ctf-remote.sock"


def _socket_path() -> Path:
    current = Path.cwd().resolve()
    for directory in (current, *current.parents):
        candidate = directory / SOCKET_NAME
        try:
            info = candidate.lstat()
        except OSError:
            pass
        else:
            if stat.S_ISSOCK(info.st_mode) and not candidate.is_symlink():
                return candidate
        if str(directory) == "/solver-scratch":
            break
    raise RuntimeError("this solver job has no authorized remote relay")


def _copy_stdin(connection: socket.socket) -> None:
    try:
        while data := os.read(sys.stdin.fileno(), 65_536):
            connection.sendall(data)
        connection.shutdown(socket.SHUT_WR)
    except (BrokenPipeError, ConnectionError, OSError):
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ctf-connect",
        description="Connect stdin/stdout to this job's single authorized CTF remote.",
    )
    parser.add_argument(
        "--socket-path",
        action="store_true",
        help="print the verified job-scoped Unix relay socket path and exit",
    )
    options = parser.parse_args(argv)
    try:
        socket_path = _socket_path()
        if options.socket_path:
            print(socket_path)
            return 0
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(str(socket_path))
        upload = threading.Thread(target=_copy_stdin, args=(connection,), daemon=True)
        upload.start()
        while data := connection.recv(65_536):
            os.write(sys.stdout.fileno(), data)
        upload.join(timeout=0.2)
        return 0
    except (OSError, RuntimeError) as exc:
        sys.stderr.write(f"ctf-connect: {exc}\n")
        return 1
    finally:
        try:
            connection.close()
        except (NameError, OSError):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
