"""Harden a child process before replacing it with the Codex app-server."""

from __future__ import annotations

import os
import sys

from .solver_worker import harden_current_process


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(64)
    harden_current_process()
    if os.name == "posix":
        os.setsid()
    executable = os.path.realpath(sys.argv[1])
    if not os.path.isfile(executable) or os.access(executable, os.X_OK) is False:
        raise SystemExit(69)
    os.execve(executable, [executable, *sys.argv[2:]], dict(os.environ))


if __name__ == "__main__":
    main()
