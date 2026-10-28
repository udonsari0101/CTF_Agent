"""Build and verify the local policy overlay without misidentifying it as GHCR."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ('Dockerfile.local-runtime', 'ctf_agent/solver_worker.py',
         'compose.local.yaml', 'deploy/local-seccomp.json', 'deploy/local_runtime.py',
         'deploy/local-compose.py')
LABEL = 'io.github.ctf-agent.local-runtime'


def inspect(image: str) -> dict:
    result = subprocess.run(['docker', 'image', 'inspect', image], check=True,
                            capture_output=True, text=True)
    return json.loads(result.stdout)[0]


def identity(root: Path = ROOT) -> tuple[str, str, dict[str, str]]:
    reference = root / '.image-ref'
    if reference.is_symlink():
        raise RuntimeError('Invalid public release image reference')
    base = reference.read_text(encoding='ascii').strip()
    if not re.fullmatch(r'ghcr.io/udonsari0101/ctf-agent-public@sha256:[0-9a-f]{64}', base):
        raise RuntimeError('Invalid public release image reference')
    hashes = {}
    for name in FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('Local runtime patch files are unavailable')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    fingerprint = hashlib.sha256(json.dumps({'base': base, 'files': hashes},
                                sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return base, fingerprint, hashes


def select_image(root: Path = ROOT) -> str:
    base, fingerprint, hashes = identity(root)
    path = root / '.local-runtime.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise RuntimeError('Local runtime identity is missing. Rerun the patched installer.')
    saved = json.loads(path.read_text(encoding='utf-8'))
    runtime_id = saved.get('runtime_id', '')
    if (saved.get('base_ref') != base or saved.get('fingerprint') != fingerprint
            or saved.get('files') != hashes
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', runtime_id)):
        raise RuntimeError('Local runtime patch identity changed. Rerun the patched installer.')
    upstream = inspect(base)
    revision = (root / '.release-revision').read_text(encoding='ascii').strip()
    labels = upstream['Config'].get('Labels') or {}
    if (upstream['Id'] != saved.get('base_id')
            or labels.get('org.opencontainers.image.revision') != revision
            or labels.get('org.opencontainers.image.source') != 'https://github.com/udonsari0101/CTF_Agent'):
        raise RuntimeError('Public runtime base identity does not match this release')
    runtime = inspect(runtime_id)
    labels = runtime['Config'].get('Labels') or {}
    if (runtime['Id'] != runtime_id or labels.get(LABEL) != fingerprint
            or labels.get('org.opencontainers.image.revision') != revision):
        raise RuntimeError('Local runtime image identity does not match this installation')
    return runtime_id


def build_image(root: Path = ROOT) -> str:
    base, fingerprint, hashes = identity(root)
    tag = 'ctf-agent-local-runtime:' + fingerprint
    try:
        existing = inspect(tag)
    except subprocess.CalledProcessError:
        existing = None
    if existing is None or (existing['Config'].get('Labels') or {}).get(LABEL) != fingerprint:
        # The pinned base is public. Isolate the anonymous build's registry
        # configuration from the Windows credential helper and user credentials.
        with tempfile.TemporaryDirectory(prefix='ctf-agent-public-runtime-') as config:
            env = dict(os.environ, DOCKER_CONFIG=config)
            subprocess.run(['docker', 'build', '--pull=false', '--file', 'Dockerfile.local-runtime',
                '--build-arg', 'BASE_IMAGE=' + base,
                '--build-arg', 'LOCAL_RUNTIME_FINGERPRINT=' + fingerprint,
                '--tag', tag, '.'], cwd=root, env=env, stdout=sys.stderr, check=True)
    upstream, runtime = inspect(base), inspect(tag)
    saved = {'base_ref': base, 'base_id': upstream['Id'], 'runtime_id': runtime['Id'],
             'fingerprint': fingerprint, 'files': hashes}
    fd, name = tempfile.mkstemp(prefix='.local-runtime.', dir=root)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            # The installer may run as root, but Start runs as the WSL user
            # who owns the release directory. Keep metadata private to them.
            if os.name == 'posix' and os.geteuid() == 0:
                owner = root.stat()
                os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
            if os.name == 'posix':
                os.fchmod(stream.fileno(), 0o600)
            json.dump(saved, stream, sort_keys=True, separators=(',', ':'))
            stream.write('\n')
        os.replace(temporary, root / '.local-runtime.json')
    finally:
        temporary.unlink(missing_ok=True)
    return select_image(root)


if __name__ == '__main__':
    if sys.argv[1:] not in (['build'], ['select']):
        raise SystemExit('Expected build or select')
    print(build_image() if sys.argv[1] == 'build' else select_image())
