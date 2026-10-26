"""Verify that the public local bundle is installable and contains no runtime data."""

import tempfile
import unittest
import zipfile
import os
import subprocess
from pathlib import Path

from scripts.package_local_release import create_archive


class LocalReleaseTest(unittest.TestCase):
    def test_bundle_has_local_stack_and_excludes_runtime_data(self):
        version = "v0.1.0"
        revision = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "local.zip"
            checksum = create_archive(version, revision, archive_path)
            self.assertIn(archive_path.name, checksum)
            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
                prefix = f"CTF_Agent-{version}/"
                for expected in (
                    "Install.cmd",
                    "Install.ps1",
                    "README.txt",
                    "VERSION",
                    "COMMIT",
                    "installer/install.sh",
                    "app/.dockerignore",
                    "app/Dockerfile",
                    "app/compose.local.yaml",
                    "app/deploy/local-compose.py",
                    "app/ctf_agent/main.py",
                    "app/ctf_agent/web/icon.svg",
                    "app/ctf_agent/web/i18n/manifest.json",
                    "app/ctf_agent/web/i18n/en.json",
                    "app/ctf_agent/web/i18n/ko.json",
                ):
                    self.assertIn(prefix + expected, names)
                self.assertTrue(all(name.startswith(prefix) for name in names))
                self.assertFalse(any("auth.json" in name for name in names))
                self.assertFalse(any(".sqlite" in name or "/.local/" in name for name in names))
                self.assertNotIn(b"\r\n", archive.read(prefix + "installer/install.sh"))

    @unittest.skipUnless(os.name == "posix", "Shell installer runs in WSL/Linux")
    def test_installer_preserves_data_across_releases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binaries = root / "bin"
            binaries.mkdir()
            for name, content in {
                "docker": "#!/bin/sh\nif [ \"$1 $2\" = 'image inspect' ]; then printf 'sha256:toolchain\\n'; exit 0; fi\nif [ \"$1\" = build ]; then printf 'build\\n' >> \"$BUILD_LOG\"; fi\nexit 0\n",
                "python3": "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$CTF_AUTH_MODE\" \"$CTF_LOCAL_DATA\" \"$CTF_LOCAL_DATABASE\" >> \"$INSTALL_LOG\"\n",
            }.items():
                executable = binaries / name
                executable.write_text(content, encoding="utf-8")
                executable.chmod(0o755)
            home = root / "persistent"
            log = root / "install.log"
            build_log = root / "build.log"
            for version, revision in (("v0.1.0", "a" * 40), ("v0.1.1", "b" * 40)):
                archive_path = root / (version + ".zip")
                create_archive(version, revision, archive_path)
                with zipfile.ZipFile(archive_path) as archive:
                    archive.extractall(root / "unpacked")
                bundle = root / "unpacked" / f"CTF_Agent-{version}"
                result = subprocess.run(
                    ["bash", str(bundle / "installer/install.sh")],
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "PATH": f"{binaries}:{os.environ['PATH']}",
                        "CTF_LOCAL_HOME": str(home),
                        "INSTALL_LOG": str(log),
                        "BUILD_LOG": str(build_log),
                    },
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((home / "releases" / version / "Dockerfile").is_file())
                marker = home / "ctf_agent_data" / "keep.txt"
                if version == "v0.1.0":
                    marker.write_text("challenge data", encoding="utf-8")
                else:
                    self.assertEqual(marker.read_text(encoding="utf-8"), "challenge data")
            self.assertEqual(len(log.read_text(encoding="utf-8").splitlines()), 2)
            self.assertEqual(build_log.read_text(encoding="utf-8").splitlines(), ["build"])
            self.assertTrue(all(line.startswith("password|") for line in log.read_text(encoding="utf-8").splitlines()))
            self.assertTrue((home / "ctf_agent_data").is_dir())
            self.assertTrue((home / "Database/CTF_Agent").is_dir())


if __name__ == "__main__":
    unittest.main()
