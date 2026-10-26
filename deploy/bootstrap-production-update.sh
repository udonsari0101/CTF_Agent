#!/bin/sh
# One-time install for an existing server distribution using a registry image.
set -eu
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH

[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
[ "$#" -eq 4 ] || {
    echo 'Usage: bootstrap-production-update.sh RELEASE_ROOT REPOSITORY IMAGE CURRENT_VERSION' >&2
    exit 1
}
release_root=$1
repository=$2
image=$3
current_version=$4
case "$release_root" in /*) ;; *) echo 'Release root must be absolute.' >&2; exit 1 ;; esac
case "$release_root" in *[!A-Za-z0-9/_-]*|'') exit 1 ;; esac
case "$repository" in */*) ;; *) echo 'Invalid release repository.' >&2; exit 1 ;; esac
case "$repository" in *[!A-Za-z0-9_./-]*|'') exit 1 ;; esac
case "$image" in */*) ;; *) echo 'Invalid image repository.' >&2; exit 1 ;; esac
case "$image" in *[!a-z0-9_./:-]*|'') exit 1 ;; esac
case "$current_version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) exit 1 ;; esac
[ -d "$release_root" ] && [ ! -L "$release_root" ] || exit 1
[ "$(readlink -f "$release_root")" = "$release_root" ] || exit 1
[ -f "$release_root/current" ] && [ ! -L "$release_root/current" ] || exit 1
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
helper=$repo_root/deploy/production-update.py
rollout=$repo_root/.github/scripts/remote-rollout.sh
[ -f "$helper" ] && [ ! -L "$helper" ] || exit 1
[ -f "$rollout" ] && [ ! -L "$rollout" ] || exit 1
python3 -m py_compile "$helper"
sh -n "$rollout"
control_dir=$(dirname "$release_root")/update-control
[ ! -e "$control_dir/current-version.json" ] && [ ! -L "$control_dir/current-version.json" ] || {
    echo 'Current version marker already exists; refusing to replace it.' >&2
    exit 1
}

install -d -o root -g root -m 0755 /usr/local/libexec /etc/ctf-agent
install -o root -g root -m 0555 "$helper" /usr/local/libexec/ctf-agent-production-update.py
install -o root -g root -m 0555 "$rollout" /usr/local/libexec/ctf-agent-remote-rollout.sh
config=/etc/ctf-agent/production-update.json
python3 - "$config" "$release_root" "$repository" "$image" <<'PY'
import json, os, sys
path, release_root, repository, image = sys.argv[1:]
data = {
    "release_root": release_root,
    "rollout_script": "/usr/local/libexec/ctf-agent-remote-rollout.sh",
    "repository": repository,
    "image": image,
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(data, output, separators=(",", ":"))
    output.write("\n")
PY
python3 /usr/local/libexec/ctf-agent-production-update.py \
    --config "$config" --bootstrap-version "$current_version"

unit=/etc/systemd/system/ctf-agent-production-update.service
temporary=$unit.tmp
cat > "$temporary" <<'EOF'
[Unit]
Description=CTF Agent production release updater
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/bin/python3 /usr/local/libexec/ctf-agent-production-update.py --config /etc/ctf-agent/production-update.json
Restart=always
RestartSec=5
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$temporary"
mv "$temporary" "$unit"
systemctl daemon-reload
systemctl enable --now ctf-agent-production-update.service >/dev/null
systemctl is-active --quiet ctf-agent-production-update.service
echo 'Production update controller is ready.'
