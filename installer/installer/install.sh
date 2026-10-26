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
toolchain_stamp="$home_dir/.toolchain-image"
toolchain_fingerprint="$(sha256sum Dockerfile.toolchain toolchain.lock requirements.txt requirements-ctf.txt deploy/DecompileAll.java deploy/DecompileFn.java | sha256sum | cut -d ' ' -f 1)"
toolchain_image="$(docker image inspect --format '{{.Id}}' ctf-agent-toolchain:local 2>/dev/null || true)"
if [[ -z "$toolchain_image" || "$(cat -- "$toolchain_stamp" 2>/dev/null || true)" != "$toolchain_fingerprint $toolchain_image" ]]; then
    docker build --file Dockerfile.toolchain --tag ctf-agent-toolchain:local .
    toolchain_image="$(docker image inspect --format '{{.Id}}' ctf-agent-toolchain:local)"
    [[ -n "$toolchain_image" ]] || { echo 'Toolchain image inspection failed.' >&2; exit 1; }
    stamp_temp="$(mktemp "$home_dir/.toolchain-image.XXXXXXXX")"
    printf '%s %s\n' "$toolchain_fingerprint" "$toolchain_image" > "$stamp_temp"
    chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$stamp_temp"
    mv -f -- "$stamp_temp" "$toolchain_stamp"
else
    echo 'Reusing the existing CTF toolchain image.'
fi
python3 deploy/local-compose.py up -d --build
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
