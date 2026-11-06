#!/bin/sh
# Install.ps1 runs this as root in the selected WSL distribution before Docker
# Desktop connects to it. Each step only adds what is missing, so it is safe to
# repeat and works on a distribution that has never been started.
# Usage: prepare-wsl.sh <current default user>
set -eu
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

default_user="$1"
changed=0

missing_commands() {
    for tool in bash python3 lsblk wipefs mkfs.ext4 blkid findmnt mount; do
        command -v "$tool" >/dev/null 2>&1 || printf '%s ' "$tool"
    done
}

python_supported() {
    python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' 2>/dev/null
}

if [ -n "$(missing_commands)" ] || ! python_supported; then
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Required tools are missing and this distribution has no apt-get: $(missing_commands)" >&2
        exit 3
    fi
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        bash python3 util-linux mount e2fsprogs
    if [ -n "$(missing_commands)" ] || ! python_supported; then
        echo "Python 3.10+ and these tools are required: $(missing_commands)" >&2
        exit 3
    fi
fi

# Containers run with this user's UID and the solver refuses UID 0. A distribution
# installed with --no-launch has only root until its first-run setup finishes.
service_user="$default_user"
if [ "$(id -u "$service_user")" = 0 ]; then
    service_user="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ { print $1; exit }' /etc/passwd)"
    if [ -z "$service_user" ]; then
        service_user=ctfagent
        useradd --create-home --shell /bin/bash "$service_user"
    fi
    if [ -f /etc/wsl.conf ] && grep -q '^\[user\]' /etc/wsl.conf; then
        sed -i '/^\[user\]/,/^\[/{/^default[[:space:]]*=/d}' /etc/wsl.conf
        sed -i "/^\[user\]/a default=$service_user" /etc/wsl.conf
    else
        printf '\n[user]\ndefault=%s\n' "$service_user" >> /etc/wsl.conf
    fi
    changed=1
fi

# Docker Desktop's integration agent runs "mkdir -p ~/.docker/run" as this user
# and reports "WSL integration unexpectedly stopped" when the home is missing.
home_dir="$(getent passwd "$service_user" | cut -d: -f6)"
primary_group="$(id -gn "$service_user")"
if [ ! -d "$home_dir" ]; then
    install -d -m 0755 -o "$service_user" -g "$primary_group" "$home_dir"
    if [ -d /etc/skel ]; then
        cp -rT /etc/skel "$home_dir"
        chown -R "$service_user:$primary_group" "$home_dir"
    fi
    changed=1
fi

if ! id -nG "$service_user" | tr ' ' '\n' | grep -qx docker; then
    groupadd -f docker
    usermod -aG docker "$service_user"
    changed=1
fi

printf 'ready user=%s changed=%s\n' "$service_user" "$changed"
