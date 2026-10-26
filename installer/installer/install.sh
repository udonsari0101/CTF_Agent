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
if [[ -L "$releases" || -L "$target" ]]; then
    echo 'Release path must not be a symlink.' >&2
    exit 2
fi
if [[ ! -d "$target" ]]; then
    staging="$(mktemp -d "$releases/.staging.XXXXXXXX")"
    trap 'rm -rf -- "$staging"' EXIT
    cp -R -- "$bundle_root/app/." "$staging/"
    mkdir -p -- "$staging/installer"
    cp -- "$bundle_root/installer/start.sh" "$bundle_root/installer/uninstall.py" "$staging/installer/"
    printf '%s\n' "$revision" > "$staging/.release-revision"
    mv -- "$staging" "$target"
    trap - EXIT
elif [[ "$(cat -- "$target/.release-revision" 2>/dev/null || true)" != "$revision" ]]; then
    echo 'An installed release with this version has different contents.' >&2
    exit 2
fi

export CTF_AUTH_MODE="${CTF_LOCAL_AUTH_MODE:-password}"
[[ "$CTF_AUTH_MODE" == password || "$CTF_AUTH_MODE" == nologin ]] || { echo 'Invalid authentication mode.' >&2; exit 2; }
export CTF_ALLOW_WEB_BOOTSTRAP=true
export CTF_LOCAL_UID="${CTF_LOCAL_UID:-$(id -u)}"
export CTF_LOCAL_GID="${CTF_LOCAL_GID:-$(id -g)}"
if [[ "$(id -u)" == 0 ]]; then
    chown -R -- "$CTF_LOCAL_UID:$CTF_LOCAL_GID" "$target"
fi
case "${CTF_LOCAL_AUTOSTART:-true}" in
    true) export CTF_LOCAL_RESTART_POLICY=unless-stopped ;;
    false) export CTF_LOCAL_RESTART_POLICY=no ;;
    *) echo 'CTF_LOCAL_AUTOSTART must be true or false.' >&2; exit 2 ;;
esac
export CTF_LOCAL_DATA="${CTF_LOCAL_DATA:-$home_dir/ctf_agent_data}"
export CTF_LOCAL_DATABASE="${CTF_LOCAL_DATABASE:-$home_dir/Database/CTF_Agent}"
export CTF_LOCAL_FS_DATA="${CTF_LOCAL_FS_DATA:-$home_dir/ctf_agent_data}"
export CTF_LOCAL_FS_DATABASE="${CTF_LOCAL_FS_DATABASE:-$home_dir/Database/CTF_Agent}"
export CTF_RELEASE_SHA="$revision"
export CTF_RELEASE_VERSION="$version"
cd -- "$target"
image_repository=ghcr.io/udonsari0101/ctf-agent-public
image_tag="$image_repository:$revision"
# Resolve the immutable registry digest before pulling. This is the same
# release image used by the server, including its CTF toolchain layers.
image_digest="$(docker manifest inspect --verbose "$image_tag" | python3 -c '
import json, re, sys
manifest = json.load(sys.stdin)
descriptor = manifest.get("Descriptor") if isinstance(manifest, dict) else None
digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("Published release image digest is invalid")
print(digest)
')"
image_ref="$image_repository@$image_digest"
docker pull "$image_ref"
image_revision="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image_ref")"
image_source="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$image_ref")"
if [[ "$image_revision" != "$revision" || "$image_source" != "https://github.com/udonsari0101/CTF_Agent" ]]; then
    echo 'Published image does not match this release.' >&2
    exit 1
fi
image_ref_temp="$(mktemp "$target/.image-ref.XXXXXXXX")"
printf '%s\n' "$image_ref" > "$image_ref_temp"
if [[ "$(id -u)" == 0 ]]; then
    chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$image_ref_temp"
fi
mv -f -- "$image_ref_temp" "$target/.image-ref"
# The installed web coordinator stops claiming queued work while this file
# exists. Wait for every claimed solve to finish before Compose recreates its
# worker; a timed-out update leaves the current workers running.
drain_file="$CTF_LOCAL_FS_DATA/deployment-drain"
if [[ -L "$CTF_LOCAL_FS_DATA" ]]; then
    echo 'The data path must not be a symlink.' >&2
    exit 1
fi
mkdir -p -- "$CTF_LOCAL_FS_DATA"
if [[ -e "$drain_file" || -L "$drain_file" ]]; then
    if [[ -f "$drain_file" && ! -L "$drain_file" ]] &&
       (( $(date +%s) - $(stat -c %Y -- "$drain_file") >= 7200 )); then
        rm -f -- "$drain_file"
    else
        echo 'Another deployment drain is active.' >&2
        exit 1
    fi
fi
if ! (set -C; : > "$drain_file"); then
    echo 'Could not reserve the deployment drain.' >&2
    exit 1
fi
trap 'rm -f -- "$drain_file"' EXIT
drain_deadline=$(( $(date +%s) + 3300 ))
while :; do
    claimed="$(python3 - "$CTF_LOCAL_FS_DATABASE/sqlite/ctf_agent.sqlite3" <<'PY'
import sqlite3
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    print(0)
else:
    with sqlite3.connect(path, timeout=15) as db:
        table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='solver_slots'").fetchone()
        print(db.execute("SELECT COUNT(*) FROM solver_slots").fetchone()[0] if table else 0)
PY
)"
    [[ "$claimed" =~ ^[0-9]+$ ]] || exit 1
    if (( claimed == 0 )); then break; fi
    if (( $(date +%s) >= drain_deadline )); then
        echo 'Active solver jobs did not finish before the update window expired.' >&2
        exit 1
    fi
    echo "Waiting for $claimed active solver job(s) before update."
    sleep 10
done
docker image tag "$image_ref" ctf-agent-local:latest
python3 deploy/local-compose.py up -d --no-build
install -d -m 0750 -o "$CTF_LOCAL_UID" -g "$CTF_LOCAL_GID" "$home_dir/.launcher"
for name in start.sh uninstall.py; do
    cp -- "$target/installer/$name" "$home_dir/.launcher/$name"
    chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$home_dir/.launcher/$name"
    chmod 0644 "$home_dir/.launcher/$name"
done
local_config_temp="$(mktemp "$home_dir/.local-config.XXXXXXXX")"
printf '{"auth_mode":"%s","auto_start":%s}\n' "$CTF_AUTH_MODE" "${CTF_LOCAL_AUTOSTART:-true}" > "$local_config_temp"
chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$local_config_temp"
mv -f -- "$local_config_temp" "$home_dir/.local-config.json"
if [[ "${CTF_UPDATE_IN_PROGRESS:-false}" != true ]]; then
    current_temp="$(mktemp "$home_dir/.current-release.XXXXXXXX")"
    printf '%s\n' "$version" > "$current_temp"
    chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$current_temp"
    mv -f -- "$current_temp" "$home_dir/.current-release"
fi
install -d -m 0700 -o "$CTF_LOCAL_UID" -g "$CTF_LOCAL_GID" "$home_dir/ctf_agent_data/update-control"
if [[ "${CTF_UPDATE_IN_PROGRESS:-false}" != true ]]; then
    updater_fingerprint="$(sha256sum Dockerfile.updater ctf_agent/release_updates.py | sha256sum | cut -d ' ' -f 1)"
    updater_stamp="$home_dir/.updater-image"
    if ! docker image inspect ctf-agent-updater:local >/dev/null 2>&1 ||
       [[ "$(cat -- "$updater_stamp" 2>/dev/null || true)" != "$updater_fingerprint" ]]; then
        docker build --file Dockerfile.updater --tag ctf-agent-updater:local .
        printf '%s\n' "$updater_fingerprint" > "$updater_stamp"
    fi
    docker rm -f ctf_agent_local_updater >/dev/null 2>&1 || true
    docker run -d --name ctf_agent_local_updater --restart "$CTF_LOCAL_RESTART_POLICY" \
        --memory 1g --cpus 1 --security-opt no-new-privileges \
        -e "CTF_LOCAL_HOME=$home_dir" -e "CTF_LOCAL_UID=$CTF_LOCAL_UID" -e "CTF_LOCAL_GID=$CTF_LOCAL_GID" \
        -v "$home_dir:$home_dir" -v /var/run/docker.sock:/var/run/docker.sock \
        ctf-agent-updater:local >/dev/null
fi
printf '\nCTF Agent %s installed. Open http://127.0.0.1:5050\n' "$version"
printf 'Data: %s\n' "$CTF_LOCAL_DATA"
