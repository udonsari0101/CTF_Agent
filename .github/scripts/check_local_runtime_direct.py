"""The local release must use the verified GHCR image without an overlay build."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from deploy import local_runtime


REVISION = 'a' * 40
BASE = 'ghcr.io/udonsari0101/ctf-agent-public@sha256:' + 'b' * 64
IMAGE_ID = 'sha256:' + 'c' * 64


class DirectRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix='ctf-agent-direct-runtime-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in local_runtime.FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + '\n', encoding='utf-8')
        (self.root / '.image-ref').write_text(BASE + '\n', encoding='ascii')
        (self.root / '.release-revision').write_text(REVISION + '\n', encoding='ascii')
        self.worker_hash = hashlib.sha256(
            (self.root / 'ctf_agent/solver_worker.py').read_bytes()
        ).hexdigest()
        self.image = {'Id': IMAGE_ID, 'Config': {'Labels': {
            'org.opencontainers.image.revision': REVISION,
            'org.opencontainers.image.source': local_runtime.SOURCE,
        }}}

    def test_pinned_image_is_selected_without_build(self) -> None:
        with patch.object(local_runtime, 'inspect', return_value=self.image) as inspect:
            with patch.object(local_runtime.subprocess, 'run', return_value=SimpleNamespace(
                stdout=self.worker_hash + '  /app/ctf_agent/solver_worker.py\n'
            )) as run:
                self.assertEqual(local_runtime.build_image(self.root), IMAGE_ID)
                self.assertEqual(local_runtime.select_image(self.root), IMAGE_ID)
        inspect.assert_called_with(BASE)
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[:3], ['docker', 'run', '--rm'])
        self.assertIn('--pull=never', arguments)
        self.assertNotIn('build', arguments)

    def test_mismatched_worker_is_rejected_before_metadata_write(self) -> None:
        with patch.object(local_runtime, 'inspect', return_value=self.image):
            with patch.object(local_runtime.subprocess, 'run', return_value=SimpleNamespace(
                stdout='0' * 64 + '  /app/ctf_agent/solver_worker.py\n'
            )):
                with self.assertRaisesRegex(RuntimeError, 'differs'):
                    local_runtime.build_image(self.root)
        self.assertFalse((self.root / '.local-runtime.json').exists())

    def test_release_file_change_invalidates_saved_identity(self) -> None:
        with patch.object(local_runtime, 'inspect', return_value=self.image):
            with patch.object(local_runtime.subprocess, 'run', return_value=SimpleNamespace(
                stdout=self.worker_hash + '  /app/ctf_agent/solver_worker.py\n'
            )):
                local_runtime.build_image(self.root)
            (self.root / 'compose.local.yaml').write_text('changed\n', encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                local_runtime.select_image(self.root)


if __name__ == '__main__':
    unittest.main()
