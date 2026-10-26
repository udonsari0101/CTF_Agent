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
config=/etc/ctf-agent/production-update.json
marker=$control_dir/current-version.json
python3 - "$config" "$marker" "$release_root" "$repository" "$image" "$current_version" <<'PY'
import json, os, re, stat, sys
config, marker, release_root, repository, image, version = sys.argv[1:]
if not re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version):
    raise SystemExit('Invalid current version')
with open(os.path.join(release_root, 'current'), encoding='ascii') as stream:
    revision = stream.read().strip()
if not re.fullmatch(r'[0-9a-f]{40}', revision):
    raise SystemExit('Invalid current release revision')
expected_config = {
    "release_root": release_root,
    "rollout_script": "/usr/local/libexec/ctf-agent-remote-rollout.sh",
    "repository": repository,
    "image": image,
}
expected_marker = {'tag': version, 'revision': revision, 'repository': repository}
for path, expected, private in ((config, expected_config, True), (marker, expected_marker, False)):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(info.st_mode) or (private and (info.st_uid != 0 or info.st_mode & 0o077)):
        raise SystemExit('An existing updater file has invalid ownership or type')
    with open(path, encoding='utf-8') as stream:
        if json.load(stream) != expected:
            raise SystemExit('An existing updater installation does not match these arguments')
PY
install -d -o root -g root -m 0755 /usr/local/libexec /etc/ctf-agent
install_if_absent() {
    source=$1
    target=$2
    if [ -e "$target" ] || [ -L "$target" ]; then
        [ -f "$target" ] && [ ! -L "$target" ] && [ "$(stat -c %u "$target")" -eq 0 ] &&
            cmp -s "$source" "$target" || {
                echo 'An installed updater file differs from this release.' >&2
                exit 1
            }
    else
        install -o root -g root -m 0555 "$source" "$target"
    fi
}
install_if_absent "$helper" /usr/local/libexec/ctf-agent-production-update.py
install_if_absent "$rollout" /usr/local/libexec/ctf-agent-remote-rollout.sh
if [ ! -e "$config" ]; then
    python3 - "$config" "$release_root" "$repository" "$image" <<'PY'
import json, os, sys
path, release_root, repository, image = sys.argv[1:]
data = {
    'release_root': release_root,
    'rollout_script': '/usr/local/libexec/ctf-agent-remote-rollout.sh',
    'repository': repository,
    'image': image,
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
    json.dump(data, output, separators=(',', ':'))
    output.write('\n')
PY
fi
if [ ! -e "$marker" ]; then
python3 /usr/local/libexec/ctf-agent-production-update.py \
    --config "$config" --bootstrap-version "$current_version"
fi

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
if [ -e "$unit" ] || [ -L "$unit" ]; then
    [ -f "$unit" ] && [ ! -L "$unit" ] && [ "$(stat -c %u "$unit")" -eq 0 ] &&
        cmp -s "$temporary" "$unit" || {
            echo 'An installed updater service differs from this release.' >&2
            exit 1
        }
    rm -f "$temporary"
else
    mv "$temporary" "$unit"
fi
systemctl daemon-reload
systemctl enable ctf-agent-production-update.service >/dev/null
systemctl start ctf-agent-production-update.service
systemctl is-active --quiet ctf-agent-production-update.service
echo 'Production update controller is ready.'
