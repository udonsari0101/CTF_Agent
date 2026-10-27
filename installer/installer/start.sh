#!/usr/bin/env bash
set -euo pipefail

home_dir="${CTF_LOCAL_HOME:?CTF_LOCAL_HOME is required}"
if [[ "$home_dir" != /* || "$home_dir" == / || -L "$home_dir" ]]; then
    echo 'Invalid CTF Agent installation path.' >&2
    exit 2
fi
version="$(cat -- "$home_dir/.current-release")"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
    echo 'Installed release metadata is invalid.' >&2
    exit 2
fi
release="$home_dir/releases/$version"
if [[ -L "$release" || ! -f "$release/.release-revision" || ! -f "$release/compose.local.yaml" ]]; then
    echo 'Installed release files are missing.' >&2
    exit 2
fi
revision="$(cat -- "$release/.release-revision")"
if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo 'Installed release revision is invalid.' >&2
    exit 2
fi
config="$home_dir/.local-config.json"
if [[ ! -f "$config" || -L "$config" ]]; then
    echo 'Local installation settings are missing.' >&2
    exit 2
fi
mapfile -t options < <(python3 - "$config" "$home_dir" <<'PY'
import json, pathlib, re, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
mode, auto = value.get("auth_mode"), value.get("auto_start")
if mode not in {"password", "nologin"} or type(auto) is not bool:
    raise SystemExit("Invalid local installation settings")
home = pathlib.Path(sys.argv[2])
default_database = home / "Database" / "CTF_Agent"
database = pathlib.Path(value.get("database_path", str(default_database)))
mount = value.get("database_mount", "")
volume_id = value.get("database_volume_id", "")
if not isinstance(mount, str) or not isinstance(volume_id, str):
    raise SystemExit("Invalid external database settings")
if mount:
    if (not re.fullmatch(r"/mnt/wsl/[A-Za-z0-9_-]+", mount)
            or database != pathlib.Path(mount) / "Database" / "CTF_Agent"
            or not re.fullmatch(r"[0-9a-f]{32}", volume_id)):
        raise SystemExit("Invalid external database settings")
    root = pathlib.Path(mount)
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        mounted = any(
            line.split(" - ", 1)[0].split()[4] == mount
            and line.split(" - ", 1)[1].split()[0] == "ext4"
            for line in stream if " - " in line
        )
    marker = root / ".ctf-agent-db-volume"
    if (not mounted or root.is_symlink() or not root.is_dir()
            or marker.is_symlink() or not marker.is_file()
            or marker.stat().st_size > 64
            or marker.read_text(encoding="ascii").strip() != volume_id):
        raise SystemExit("The configured external database VHD is unavailable")
    for path in (root / "Database", database):
        if path.is_symlink():
            raise SystemExit("The external database path contains a symlink")
else:
    if database != default_database or volume_id:
        raise SystemExit("Invalid local database settings")
print(mode)
print("true" if auto else "false")
print(database)
print(mount)
print(volume_id)
PY
)
if [[ "${#options[@]}" -ne 5 ]]; then
    echo 'Local installation settings are invalid.' >&2
    exit 2
fi
docker info >/dev/null
docker image inspect ctf-agent-local:latest >/dev/null
image_revision="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' ctf-agent-local:latest)"
if [[ "$image_revision" != "$revision" ]]; then
    echo 'Installed image does not match the selected release.' >&2
    exit 1
fi
if [[ -f "$release/.image-ref" ]]; then
    if [[ -L "$release/.image-ref" ]]; then
        echo 'Installed image reference is invalid.' >&2
        exit 1
    fi
    image_ref="$(cat -- "$release/.image-ref")"
    if [[ ! "$image_ref" =~ ^ghcr\.io/udonsari0101/ctf-agent-public@sha256:[0-9a-f]{64}$ ]]; then
        echo 'Installed image reference is invalid.' >&2
        exit 1
    fi
    pinned_id="$(docker image inspect --format '{{.Id}}' "$image_ref")"
    local_id="$(docker image inspect --format '{{.Id}}' ctf-agent-local:latest)"
    if [[ -z "$pinned_id" || "$pinned_id" != "$local_id" ]]; then
        echo 'Installed image does not match its public release digest.' >&2
        exit 1
    fi
fi
export CTF_LOCAL_HOME="$home_dir"
export CTF_LOCAL_DATA="$home_dir/ctf_agent_data"
export CTF_LOCAL_DATABASE="${options[2]}"
export CTF_LOCAL_FS_DATABASE="${options[2]}"
export CTF_LOCAL_DB_MOUNT="${options[3]}"
export CTF_LOCAL_UID="$(id -u)"
export CTF_LOCAL_GID="$(id -g)"
export CTF_AUTH_MODE="${options[0]}"
export CTF_ALLOW_WEB_BOOTSTRAP=true
if [[ -n "${options[3]}" ]]; then
    # Prevent Docker Desktop from resurrecting the DB container before the
    # Windows launcher has reattached and verified the external VHD.
    export CTF_LOCAL_RESTART_POLICY=no
else
    export CTF_LOCAL_RESTART_POLICY="$( [[ "${options[1]}" == true ]] && echo unless-stopped || echo no )"
fi
export CTF_RELEASE_SHA="$revision"
export CTF_RELEASE_VERSION="$version"
cd -- "$release"
python3 deploy/local-compose.py up -d --no-build
if docker image inspect ctf-agent-updater:local >/dev/null 2>&1; then
    docker start ctf_agent_local_updater >/dev/null 2>&1 || true
fi
printf 'CTF Agent %s started at http://127.0.0.1:5050\n' "$version"
