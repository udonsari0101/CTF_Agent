#!/usr/bin/env bash
set -euo pipefail
umask 077

bundle_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
version="$(cat -- "$bundle_root/VERSION")"
revision="$(cat -- "$bundle_root/COMMIT")"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] ||
   [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo 'Invalid release metadata.' >&2
    exit 2
fi
for command in docker python3; do
    command -v "$command" >/dev/null || { echo "Missing $command in WSL." >&2; exit 2; }
done
docker info >/dev/null || { echo 'Docker Desktop is unavailable in this WSL distribution.' >&2; exit 2; }
docker compose version >/dev/null || { echo 'Docker Compose is unavailable.' >&2; exit 2; }

home_dir="${CTF_LOCAL_HOME:-$HOME/.local/share/ctf-agent}"
if [[ "$home_dir" != /* ]] || [[ -L "$home_dir" ]]; then
    echo 'CTF_LOCAL_HOME must be an absolute, non-symlink Linux path.' >&2
    exit 2
fi
releases="$home_dir/releases"
target="$releases/$version"
mkdir -p -- "$releases" "$home_dir/ctf_agent_data" "$home_dir/Database/CTF_Agent"
if [[ ! -d "$target" ]]; then
    staging="$(mktemp -d "$releases/.staging.XXXXXXXX")"
    trap 'rm -rf -- "$staging"' EXIT
    cp -R -- "$bundle_root/app/." "$staging/"
    printf '%s\n' "$revision" > "$staging/.release-revision"
    mv -- "$staging" "$target"
    trap - EXIT
elif [[ "$(cat -- "$target/.release-revision" 2>/dev/null || true)" != "$revision" ]]; then
    echo 'An installed release with this version has different contents.' >&2
    exit 2
fi

export CTF_AUTH_MODE=password
export CTF_ALLOW_WEB_BOOTSTRAP=true
export CTF_LOCAL_UID="$(id -u)"
export CTF_LOCAL_GID="$(id -g)"
export CTF_LOCAL_DATA="$home_dir/ctf_agent_data"
export CTF_LOCAL_DATABASE="$home_dir/Database/CTF_Agent"
export CTF_RELEASE_SHA="$revision"
cd -- "$target"
toolchain_stamp="$home_dir/.toolchain-image"
toolchain_fingerprint="$(sha256sum Dockerfile.toolchain toolchain.lock requirements.txt requirements-ctf.txt deploy/DecompileAll.java deploy/DecompileFn.java | sha256sum | cut -d ' ' -f 1)"
toolchain_image="$(docker image inspect --format '{{.Id}}' ctf-agent-toolchain:local 2>/dev/null || true)"
if [[ -z "$toolchain_image" || "$(cat -- "$toolchain_stamp" 2>/dev/null || true)" != "$toolchain_fingerprint $toolchain_image" ]]; then
    docker build --file Dockerfile.toolchain --tag ctf-agent-toolchain:local .
    toolchain_image="$(docker image inspect --format '{{.Id}}' ctf-agent-toolchain:local)"
    [[ -n "$toolchain_image" ]] || { echo 'Toolchain image inspection failed.' >&2; exit 1; }
    stamp_temp="$(mktemp "$home_dir/.toolchain-image.XXXXXXXX")"
    printf '%s %s\n' "$toolchain_fingerprint" "$toolchain_image" > "$stamp_temp"
    mv -f -- "$stamp_temp" "$toolchain_stamp"
else
    echo 'Reusing the existing CTF toolchain image.'
fi
python3 deploy/local-compose.py up -d --build
printf '\nCTF Agent %s installed. Open http://127.0.0.1:5050\n' "$version"
printf 'Data: %s\n' "$CTF_LOCAL_DATA"
