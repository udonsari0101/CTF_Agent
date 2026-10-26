"""Build a source-only Windows/WSL local installer ZIP from tracked files."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXED_APP_FILES = {
    ".dockerignore",
    "Dockerfile",
    "Dockerfile.toolchain",
    "toolchain.lock",
    "compose.local.yaml",
    "requirements.txt",
    "requirements-ctf.txt",
    "deploy/local-compose.py",
    "deploy/submit-flag",
    "deploy/request-remote",
    "deploy/connect-remote",
    "deploy/ctf-browser",
    "deploy/DecompileAll.java",
    "deploy/DecompileFn.java",
}
INSTALLER_FILES = {
    "installer/Install.cmd": "Install.cmd",
    "installer/Install.ps1": "Install.ps1",
    "installer/README.txt": "README.txt",
    "installer/installer/install.sh": "installer/install.sh",
}


def tracked_files() -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return {entry.decode("utf-8") for entry in result.stdout.split(b"\0") if entry}


def package_files(tracked: set[str]) -> dict[str, str]:
    app_files = {name for name in tracked if name.startswith("ctf_agent/")}
    required = FIXED_APP_FILES | set(INSTALLER_FILES)
    missing = required - tracked
    if missing:
        raise ValueError(f"Release files are not tracked: {sorted(missing)}")
    if not app_files:
        raise ValueError("No application files are tracked")
    return {
        **{name: f"app/{name}" for name in FIXED_APP_FILES | app_files},
        **INSTALLER_FILES,
    }


def create_archive(version: str, revision: str, output: Path) -> str:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("Expected a vMAJOR.MINOR.PATCH release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a full Git revision")
    mapping = package_files(tracked_files())
    prefix = f"CTF_Agent-{version}/"
    payload = {destination: (ROOT / source).read_bytes() for source, destination in mapping.items()}
    payload["VERSION"] = (version + "\n").encode()
    payload["COMMIT"] = (revision + "\n").encode()
    # Windows checkouts may use CRLF; the WSL entrypoint must always be LF.
    payload["installer/install.sh"] = payload["installer/install.sh"].replace(b"\r\n", b"\n")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(payload):
            info = zipfile.ZipInfo(prefix + name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 << 16)
            archive.writestr(info, payload[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return f"{digest}  {output.name}\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / "dist" / f"CTF_Agent-{args.version}-local-windows.zip"
    checksum = create_archive(args.version, args.commit, output)
    output.with_name(output.name + ".sha256").write_text(checksum, encoding="ascii")
    print(output)
    print(checksum, end="")


if __name__ == "__main__":
    main()
