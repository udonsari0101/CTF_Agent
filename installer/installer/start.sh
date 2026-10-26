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
mapfile -t options < <(python3 - "$config" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
mode, auto = value.get("auth_mode"), value.get("auto_start")
if mode not in {"password", "nologin"} or type(auto) is not bool:
    raise SystemExit("Invalid local installation settings")
print(mode)
print("true" if auto else "false")
PY
)
if [[ "${#options[@]}" -ne 2 ]]; then
    echo 'Local installation settings are invalid.' >&2
    exit 2
fi
docker info >/dev/null
docker image inspect ctf-agent-local:latest >/dev/null
export CTF_LOCAL_HOME="$home_dir"
export CTF_LOCAL_DATA="$home_dir/ctf_agent_data"
export CTF_LOCAL_DATABASE="$home_dir/Database/CTF_Agent"
export CTF_LOCAL_UID="$(id -u)"
export CTF_LOCAL_GID="$(id -g)"
export CTF_AUTH_MODE="${options[0]}"
export CTF_ALLOW_WEB_BOOTSTRAP=true
export CTF_LOCAL_RESTART_POLICY="$( [[ "${options[1]}" == true ]] && echo unless-stopped || echo no )"
export CTF_RELEASE_SHA="$revision"
export CTF_RELEASE_VERSION="$version"
cd -- "$release"
python3 deploy/local-compose.py up -d --no-build
if docker image inspect ctf-agent-updater:local >/dev/null 2>&1; then
    docker start ctf_agent_local_updater >/dev/null 2>&1 || true
fi
printf 'CTF Agent %s started at http://127.0.0.1:5050\n' "$version"
