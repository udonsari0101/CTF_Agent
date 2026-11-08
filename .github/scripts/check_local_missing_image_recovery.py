"""Exercise the release installer's stopped-installation image-loss path."""

from __future__ import annotations

import json
import importlib.util
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "installer" / "installer" / "install.sh"
OLD_REVISION = "a" * 40
NEW_REVISION = "b" * 40
OLD_IMAGE = "ghcr.io/udonsari0101/ctf-agent-public@sha256:" + "1" * 64


class MissingImageRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="ctf-agent-lost-image-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.database = self.home / "Database" / "CTF_Agent" / "sqlite" / "ctf_agent.sqlite3"
        self.database.parent.mkdir(parents=True)
        with sqlite3.connect(self.database) as db:
            db.executescript(
                "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);"
                "INSERT INTO meta VALUES('legacy_owner_id','owner-one');"
                "CREATE TABLE users(id TEXT);INSERT INTO users VALUES('owner-one');"
                "CREATE TABLE workspaces(id TEXT);INSERT INTO workspaces VALUES('workspace-one');"
                "CREATE TABLE solver_slots(slot_id TEXT,job_id TEXT);"
                "CREATE TABLE solver_jobs(id TEXT,status TEXT);"
            )
        self.marker = self.home / ".current-release"
        self.marker.write_text("v0.4.29\n", encoding="ascii")
        self.config = self.home / ".local-config.json"
        self.config.write_text(json.dumps({
            "auth_mode": "nologin", "auto_start": False,
            "database_path": str(self.database.parent.parent),
            "database_mount": "",
        }), encoding="utf-8")
        old_release = self.home / "releases" / "v0.4.29"
        old_release.mkdir(parents=True)
        (old_release / ".release-revision").write_text(OLD_REVISION + "\n", encoding="ascii")
        (old_release / ".image-ref").write_text(OLD_IMAGE + "\n", encoding="ascii")
        self.bundle = self.root / "bundle"
        (self.bundle / "installer").mkdir(parents=True)
        shutil.copy2(INSTALLER, self.bundle / "installer" / "install.sh")
        for name in ("start.sh", "uninstall.py", "storage_preflight.py", "storage_control.py"):
            (self.bundle / "installer" / name).write_text("fixture\n", encoding="utf-8")
        (self.bundle / "VERSION").write_text("v0.4.60\n", encoding="ascii")
        (self.bundle / "COMMIT").write_text(NEW_REVISION + "\n", encoding="ascii")
        app = self.bundle / "app"
        for name in (
            "Dockerfile.local-runtime", "compose.local.yaml",
            "ctf_agent/solver_worker.py", "ctf_agent/release_updates.py",
            "deploy/local_runtime.py", "deploy/local-compose.py",
            "deploy/local-seccomp.json", "deploy/local-seccomp.README.md",
            "deploy/moby-profiles-LICENSE", "Dockerfile.updater",
        ):
            path = app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "docker.log"
        docker = self.bin / "docker"
        docker.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -e
            printf '%s\\n' "$*" >> "$MOCK_DOCKER_LOG"
            case "$1 $2" in
                'info '|'compose version') exit 0 ;;
                'ps --all')
                    if [[ "$MOCK_CONTAINERS" == yes ]]; then
                        if [[ "$*" == *'--quiet'* ]]; then echo fake-container-id
                        else echo ctf_agent_local_solver; fi
                    fi
                    exit 0 ;;
                'image inspect')
                    if [[ "$MOCK_OLD_BASE" == yes &&
                          ( "$*" == *"$MOCK_OLD_IMAGE"* || "$*" == *"$MOCK_OLD_ID"* ) ]]; then
                        case "$*" in
                            *org.opencontainers.image.revision*) echo "$MOCK_OLD_REVISION" ;;
                            *org.opencontainers.image.source*) echo https://github.com/udonsari0101/CTF_Agent ;;
                            *--format*) echo "$MOCK_OLD_ID" ;;
                        esac
                        exit 0
                    fi
                    if [[ -f "$MOCK_PULLED" ]]; then
                        case "$*" in
                            *org.opencontainers.image.revision*) echo "$MOCK_NEW_REVISION" ;;
                            *org.opencontainers.image.source*) echo https://github.com/udonsari0101/CTF_Agent ;;
                            *--format*) echo "sha256:$(printf '2%.0s' {1..64})" ;;
                        esac
                        exit 0
                    fi
                    exit 1 ;;
                'manifest inspect')
                    printf '{"Descriptor":{"digest":"sha256:%064d"}}\\n' 0
                    exit 0 ;;
                'pull '*)
                    if [[ "$MOCK_PULL_FAILURE" == yes ]]; then exit 1; fi
                    touch "$MOCK_PULLED"
                    exit 0 ;;
                'run '*)
                    if [[ "$*" == *' reserve '* ]]; then echo reserve-token; fi
                    if [[ "$*" == *' -d --name '* ]]; then
                        mkdir -p "$MOCK_HOME/ctf_agent_data/update-control"
                        printf '{"updated_at":%s}\\n' "$(date +%s)" > "$MOCK_HOME/ctf_agent_data/update-control/status.json"
                        echo candidate-id
                    fi
                    exit 0 ;;
                'inspect --format')
                    if [[ "$*" == *'Health.Status'* ]]; then
                        if [[ "$MOCK_HEALTH_SUCCESS" == yes ]]; then echo healthy; else echo unhealthy; fi
                    elif [[ "$*" == *'.Image'* ]]; then printf 'sha256:%064d\n' 0
                    elif [[ "$*" == *'.Running'* ]]; then echo true
                    fi
                    exit 0 ;;
                'container inspect') exit 1 ;;
                'compose -f'|'image tag'|'image rm'|'build --file'|'rename '|'rm ') exit 0 ;;
            esac
            exit 0
            """), encoding="utf-8")
        docker.chmod(0o755)
        python = self.bin / "python3"
        python.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            case "$1" in
                *deploy/local-compose.py|*deploy/local_runtime.py|*installer/storage_preflight.py)
                    if [[ "$1" == *local_runtime.py ]]; then
                        printf 'sha256:%064d\\n' 0
                    fi
                    exit 0 ;;
            esac
            exec {sys.executable} "$@"
            """), encoding="utf-8")
        python.chmod(0o755)

    def add_previous_runtime_metadata(self, *, corrupt: bool = False) -> None:
        old_release = self.home / "releases" / "v0.4.29"
        script = old_release / "deploy" / "local_runtime.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "deploy" / "local_runtime.py", script)
        spec = importlib.util.spec_from_file_location("fixture_local_runtime", script)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in module.FILES:
            path = old_release / name
            if path == script:
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        base, fingerprint, hashes = module.identity(old_release)
        metadata = {
            "base_ref": base,
            "base_id": "sha256:" + "3" * 64,
            "runtime_id": "sha256:" + "4" * 64,
            "fingerprint": "broken" if corrupt else fingerprint,
            "files": hashes,
        }
        (old_release / ".local-runtime.json").write_text(
            json.dumps(metadata), encoding="utf-8")

    def run_installer(
        self, *, containers: bool = False, pull_failure: bool = False,
        old_base: bool = False, health_success: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            MOCK_DOCKER_LOG=str(self.log),
            MOCK_CONTAINERS="yes" if containers else "no",
            MOCK_PULL_FAILURE="yes" if pull_failure else "no",
            MOCK_PULLED=str(self.root / "pulled"),
            MOCK_NEW_REVISION=NEW_REVISION,
            MOCK_OLD_BASE="yes" if old_base else "no",
            MOCK_OLD_IMAGE=OLD_IMAGE,
            MOCK_OLD_ID="sha256:" + "3" * 64,
            MOCK_OLD_REVISION=OLD_REVISION,
            MOCK_HEALTH_SUCCESS="yes" if health_success else "no",
            MOCK_HOME=str(self.home),
            CTF_LOCAL_HOME=str(self.home),
            CTF_LOCAL_AUTH_MODE="nologin",
            CTF_LOCAL_AUTOSTART="false",
            CTF_LOCAL_UID=str(os.getuid()),
            CTF_LOCAL_GID=str(os.getgid()),
        )
        return subprocess.run(
            ["bash", str(self.bundle / "installer" / "install.sh")],
            env=environment, cwd=self.root, text=True, capture_output=True,
            timeout=30, check=False,
        )

    def assert_original_preserved(self) -> None:
        self.assertEqual(self.marker.read_text(encoding="ascii"), "v0.4.29\n")
        settings = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(settings["database_path"], str(self.database.parent.parent))
        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT count(*) FROM workspaces").fetchone()[0], 1)

    def inject_backup_directory_fsync_failure(self) -> None:
        installer = self.bundle / "installer" / "install.sh"
        source = installer.read_text(encoding="utf-8")
        expected = "        os.fsync(directory_descriptor)\n"
        self.assertEqual(source.count(expected), 1)
        installer.write_text(
            source.replace(
                expected,
                "        raise OSError('simulated backup directory fsync failure')\n",
            ),
            encoding="utf-8",
        )

    def test_missing_image_health_failure_preserves_database_and_stops_new_stack(self) -> None:
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("recovering the stopped installation", result.stdout)
        self.assertIn("Previous database snapshot:", result.stdout, result.stdout + result.stderr)
        snapshots = list((self.home / "recovery-backups").glob("*.sqlite3"))
        self.assertEqual(len(snapshots), 1)
        with sqlite3.connect(snapshots[0]) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM workspaces").fetchone()[0], 1)
        self.assertIn("down --remove-orphans", self.log.read_text(encoding="utf-8"))
        self.assert_original_preserved()

    def test_missing_image_with_existing_container_is_refused_before_pull(self) -> None:
        result = self.run_installer(containers=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("containers still exist", result.stderr)
        self.assertNotIn("pull ", self.log.read_text(encoding="utf-8"))
        self.assertFalse((self.home / "recovery-backups").exists())
        self.assert_original_preserved()

    def test_missing_image_with_active_slot_is_refused_before_pull(self) -> None:
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO solver_slots VALUES('solver-1','job-one')")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Active solver work remains", result.stderr)
        self.assertNotIn("pull ", self.log.read_text(encoding="utf-8"))
        self.assert_original_preserved()

    def test_failed_pull_keeps_original_database_and_marker(self) -> None:
        result = self.run_installer(pull_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("down --remove-orphans", self.log.read_text(encoding="utf-8"))
        self.assert_original_preserved()

    def test_backup_directory_fsync_failure_stops_before_new_service(self) -> None:
        self.inject_backup_directory_fsync_failure()
        result = self.run_installer(health_success=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("simulated backup directory fsync failure", result.stderr)
        docker_log = self.log.read_text(encoding="utf-8")
        self.assertNotIn("image tag", docker_log)
        self.assertNotIn("down --remove-orphans", docker_log)
        self.assert_original_preserved()

    def test_missing_runtime_image_with_valid_metadata_uses_guarded_recovery(self) -> None:
        self.add_previous_runtime_metadata()
        result = self.run_installer(old_base=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("recovering the stopped installation", result.stdout)
        self.assertIn("Previous database snapshot:", result.stdout)
        self.assertIn("down --remove-orphans", self.log.read_text(encoding="utf-8"))
        self.assert_original_preserved()

    def test_runtime_fingerprint_mismatch_is_not_recovery(self) -> None:
        self.add_previous_runtime_metadata(corrupt=True)
        result = self.run_installer(old_base=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identity does not match", result.stderr)
        self.assertNotIn("pull ", self.log.read_text(encoding="utf-8"))
        self.assert_original_preserved()

    def test_missing_images_can_complete_install_without_losing_existing_data(self) -> None:
        result = self.run_installer(health_success=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.marker.read_text(encoding="ascii"), "v0.4.60\n")
        self.assertIn("Previous database snapshot:", result.stdout)
        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT count(*) FROM workspaces").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM users").fetchone()[0], 1)
        log = self.log.read_text(encoding="utf-8")
        self.assertIn("pull ", log)
        self.assertNotIn("build --file Dockerfile.local-runtime", log)
        self.assertNotIn("down --remove-orphans", log)


if __name__ == "__main__":
    unittest.main()
