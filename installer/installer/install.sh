#!/usr/bin/env bash
set -euo pipefail
umask 077

# These release and updater base images are public. Do not invoke a user's
# Windows credential helper for anonymous registry access: WSL interop may be
# unavailable even though the Linux Docker engine and its CLI work correctly.
# Keep the user's Docker config and credentials untouched.
public_docker() (
    registry_config="$(mktemp -d /tmp/ctf-agent-public-registry.XXXXXXXX)"
    trap 'rm -rf -- "$registry_config"' EXIT
    DOCKER_CONFIG="$registry_config" docker "$@"
)

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
default_database="$home_dir/Database/CTF_Agent"
database_path="${CTF_LOCAL_DATABASE:-$default_database}"
database_fs_path="${CTF_LOCAL_FS_DATABASE:-$database_path}"
database_mount="${CTF_LOCAL_DB_MOUNT:-}"
if [[ -n "$database_mount" && "${CTF_UPDATE_IN_PROGRESS:-false}" == true &&
      "${CTF_HOST_UPDATE_ATTESTED:-false}" != true ]]; then
    echo 'An external database VHD update requires the trusted WSL launcher. The in-app updater cannot verify the host mount; do not reinstall or delete data.' >&2
    exit 2
fi
if [[ "$database_path" != /* || "$database_fs_path" != /* ]]; then
    echo 'Local database paths must be absolute.' >&2
    exit 2
fi
# A reinstall or update must keep using its original database. If the VHD was
# mounted but its SQLite file disappeared, init-storage and the web process
# would otherwise silently initialize a new, empty installation on that disk.
if [[ -e "$home_dir/.current-release" || -L "$home_dir/.current-release" ||
      -e "$home_dir/.local-config.json" || -L "$home_dir/.local-config.json" ]]; then
    existing_database="$database_fs_path/sqlite/ctf_agent.sqlite3"
    if [[ -L "$existing_database" || ! -f "$existing_database" || ! -s "$existing_database" ]]; then
        echo 'The existing local database is unavailable; refusing to replace it with an empty database.' >&2
        exit 2
    fi
    python3 - "$existing_database" <<'PY'
import pathlib, sqlite3, sys
path = pathlib.Path(sys.argv[1])
try:
    with sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('meta','users','workspaces')")}
        owner = db.execute("SELECT value FROM meta WHERE key='legacy_owner_id'").fetchone() if "meta" in tables else None
        user = db.execute("SELECT 1 FROM users LIMIT 1").fetchone() if "users" in tables else None
        if tables != {"meta", "users", "workspaces"} or not owner or not owner[0] or not user:
            raise ValueError("Required initialized data is missing")
except (sqlite3.Error, ValueError) as exc:
    raise SystemExit("The existing local database is not initialized; refusing to replace it") from exc
PY
fi
database_volume_id=""
if [[ -n "$database_mount" ]]; then
    # This runs before creating a database directory. If the D: VHD is not
    # mounted, Docker must never create a fresh database on the WSL root disk.
    database_volume_id="$(python3 - "$database_fs_path" "$database_mount" "$home_dir/.local-config.json" "$default_database" "${CTF_UPDATE_IN_PROGRESS:-false}" <<'PY'
import json, os, pathlib, re, sys

database, mount, config, default_database = map(pathlib.Path, sys.argv[1:5])
updating = sys.argv[5] == "true"
if (not mount.is_absolute() or str(mount) != os.path.normpath(str(mount))
        or not re.fullmatch(r"/mnt/wsl/[A-Za-z0-9_-]+", str(mount))
        or database != mount / "Database" / "CTF_Agent"):
    raise SystemExit("Invalid external database mount or path")
if not mount.is_dir() or mount.is_symlink():
    raise SystemExit("The external database VHD is not mounted")
with open("/proc/self/mountinfo", encoding="utf-8") as stream:
    filesystems = [
        line.split(" - ", 1)[1].split()[0]
        for line in stream if " - " in line
        if line.split(" - ", 1)[0].split()[4] == str(mount)
    ]
if not filesystems or "ext4" not in filesystems:
    raise SystemExit("The external database VHD is not mounted as ext4")
if updating and not (database / "sqlite" / "ctf_agent.sqlite3").is_file():
    raise SystemExit("The external database is unavailable during update")
for path in (mount / "Database", database):
    if path.is_symlink():
        raise SystemExit("The external database path must not contain symlinks")
prior = {}
if config.exists():
    if config.is_symlink():
        raise SystemExit("Local installation settings are invalid")
    prior = json.loads(config.read_text(encoding="utf-8"))
    previous_database = prior.get("database_path", str(default_database))
    previous_mount = prior.get("database_mount", "")
    if previous_database != str(database) or previous_mount != str(mount):
        previous_file = pathlib.Path(previous_database) / "sqlite" / "ctf_agent.sqlite3"
        if previous_file.exists():
            raise SystemExit("Existing database must be migrated before changing its location")
        raise SystemExit("Existing installation uses a different database location")
elif (default_database / "sqlite" / "ctf_agent.sqlite3").exists():
    raise SystemExit("Existing database must be migrated before changing its location")
marker = mount / ".ctf-agent-db-volume"
if marker.is_symlink():
    raise SystemExit("The external database volume marker is invalid")
if not marker.is_file() or marker.stat().st_size > 64:
    raise SystemExit("The external database volume marker is missing or invalid")
volume_id = marker.read_text(encoding="ascii").strip()
if not re.fullmatch(r"[0-9a-f]{32}", volume_id):
    raise SystemExit("The external database volume marker is invalid")
if prior and prior.get("database_volume_id") != volume_id:
    raise SystemExit("The mounted database VHD does not match this installation")
print(volume_id)
PY
)"
elif [[ "$database_fs_path" != "$default_database" ]]; then
    echo 'An external database path requires CTF_LOCAL_DB_MOUNT.' >&2
    exit 2
elif [[ -f "$home_dir/.local-config.json" ]]; then
    if ! python3 - "$home_dir/.local-config.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if value.get("database_mount"):
    raise SystemExit("External database VHD is required for this installation")
PY
    then
        exit 2
    fi
fi
releases="$home_dir/releases"
target="$releases/$version"
mkdir -p -- "$releases" "$home_dir/ctf_agent_data" "$database_fs_path"
if [[ -n "$database_mount" ]]; then
    # Docker Desktop's WSL integration resolves this home path through the
    # selected distro. A direct /mnt/wsl bind can point at an old shadow mount
    # after a reboot even when the WSL host sees the real VHD.
    database_alias="$home_dir/.database-bind"
    if [[ -L "$database_alias" ]]; then
        [[ "$(readlink -- "$database_alias")" == "$database_fs_path" ]] || {
            echo 'The database bind alias targets a different disk.' >&2; exit 2;
        }
    elif [[ -e "$database_alias" ]]; then
        echo 'The database bind alias is not a symlink.' >&2; exit 2
    else
        ln -s -- "$database_fs_path" "$database_alias"
    fi
    database_path="$database_alias"
fi
if [[ -L "$releases" || -L "$target" ]]; then
    echo 'Release path must not be a symlink.' >&2
    exit 2
fi
staging=""
previous_snapshot=""
previous_version=""
previous_release=""
previous_revision=""
previous_base_id=""
previous_runtime_id=""
settings_snapshot=""
updater_candidate=""
updater_old_exists=false
updater_old_running=false
updater_old_image=""
updater_old_renamed=false
updater_candidate_started=false
updater_promoted=false
drain_token=""
rollout_started=false
new_ready=false
cleanup_install() {
    local status=$?
    local drain_released=true
    local source_restored=true
    local settings_restored=true
    local updater_replacement_removed=true
    trap - EXIT
    if (( status != 0 )); then
        # Keep the previous update controller alive if replacing it failed.
        # The old container retains its image even after the local tag moves.
        if [[ "$updater_promoted" == true ]]; then
            if ! docker rm -f ctf_agent_local_updater >/dev/null; then
                echo 'The replacement update controller could not be removed safely.' >&2
                status=1
                updater_replacement_removed=false
            fi
        elif [[ "$updater_candidate_started" == true ]]; then
            if docker container inspect "$updater_candidate" >/dev/null 2>&1 &&
               ! docker rm -f "$updater_candidate" >/dev/null; then
                echo 'The candidate update controller could not be removed safely.' >&2
                status=1
                updater_replacement_removed=false
            fi
        fi
        if [[ "$updater_old_renamed" == true && "$updater_replacement_removed" == true ]]; then
            if ! docker rename ctf_agent_local_updater_previous ctf_agent_local_updater >/dev/null; then
                echo 'The previous update controller could not be renamed back.' >&2
                status=1
                updater_replacement_removed=false
            fi
        fi
        if [[ "$updater_old_exists" == true ]]; then
            if [[ "$updater_old_image" =~ ^sha256:[0-9a-f]{64}$ ]]; then
                docker image tag "$updater_old_image" ctf-agent-updater:local >/dev/null || status=1
            fi
            if [[ "$updater_old_running" == true && "$updater_replacement_removed" == true ]]; then
                if [[ "$(docker inspect --format '{{.State.Running}}' ctf_agent_local_updater 2>/dev/null || true)" != true ]]; then
                    docker start ctf_agent_local_updater >/dev/null || status=1
                fi
            fi
        fi
        if [[ -n "$settings_snapshot" ]]; then
            restore_setting() {
                local source="$settings_snapshot/$1" destination="$2"
                if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
                    return 1
                fi
                if [[ -f "$source" ]]; then
                    cp -p -- "$source" "$destination"
                elif [[ -f "$destination" ]]; then
                    rm -f -- "$destination"
                fi
            }
            restore_setting current-release "$home_dir/.current-release" || { status=1; settings_restored=false; }
            restore_setting local-config.json "$home_dir/.local-config.json" || { status=1; settings_restored=false; }
            restore_setting updater-image "$home_dir/.updater-image" || { status=1; settings_restored=false; }
            restore_setting launcher-start.sh "$home_dir/.launcher/start.sh" || { status=1; settings_restored=false; }
            restore_setting launcher-uninstall.py "$home_dir/.launcher/uninstall.py" || { status=1; settings_restored=false; }
        fi
    fi
    if [[ -n "$previous_snapshot" && -d "$previous_snapshot" ]]; then
        if (( status != 0 )) && [[ "$previous_version" == "$version" ]]; then
            local failed_target
            failed_target="$(mktemp -d "$releases/.failed-release.XXXXXXXX")"
            rmdir -- "$failed_target"
            if mv -- "$target" "$failed_target"; then
                if mv -- "$previous_snapshot" "$target"; then
                    previous_release="$target"
                    previous_snapshot=""
                    rm -rf -- "$failed_target"
                else
                    mv -- "$failed_target" "$target" || true
                    source_restored=false
                fi
            else
                source_restored=false
            fi
            if [[ "$source_restored" != true ]]; then
                echo 'The previous release files could not be restored automatically.' >&2
                status=1
            fi
        else
            rm -rf -- "$previous_snapshot"
        fi
    fi
    if [[ -n "$drain_token" ]]; then
        if ! manage_storage_control release "$drain_token" >/dev/null; then
            echo 'The deployment drain changed and was preserved; the previous service was not restarted.' >&2
            drain_released=false
            status=1
        fi
    fi
    if (( status != 0 )) && [[ "$rollout_started" == true && "$new_ready" != true &&
                                "${CTF_UPDATE_IN_PROGRESS:-false}" != true &&
                                "$drain_released" == true && "$source_restored" == true &&
                                "$settings_restored" == true ]]; then
        if [[ -e "$home_dir/.database-bind-failed" || -L "$home_dir/.database-bind-failed" ]]; then
            echo 'Database bind verification failed. Previous releases were not started against an unverified database.' >&2
        elif [[ -n "${database_mount:-}" &&
                ( -e "$home_dir/ctf_agent_data/update-control/stop-worker" ||
                  -L "$home_dir/ctf_agent_data/update-control/stop-worker" ) ]]; then
            echo 'Uninstall is in progress; the installer did not restart the service.' >&2
        elif [[ -n "${database_mount:-}" &&
                ( -e "$home_dir/ctf_agent_data/update-control/request.json" ||
                  -L "$home_dir/ctf_agent_data/update-control/request.json" ||
                  -e "$home_dir/ctf_agent_data/update-control/running.json" ||
                  -L "$home_dir/ctf_agent_data/update-control/running.json" ) ]]; then
            echo 'A site update is pending or running; the installer did not restart the service.' >&2
        elif [[ -n "$previous_release" ]]; then
            if ! restore_previous_service; then
                echo 'The previous service could not be restored automatically; its release and data were preserved.' >&2
            fi
        else
            # A failed first installation must not leave an unregistered web
            # stack running. Compose down keeps every bind-mounted data path.
            if ! docker compose -f "$target/compose.local.yaml" down --remove-orphans; then
                echo 'The incomplete first service could not be stopped automatically.' >&2
            fi
            echo 'No previous service exists to restore; installation data was preserved.' >&2
        fi
    fi
    if [[ -n "$staging" && -d "$staging" ]]; then rm -rf -- "$staging"; fi
    if [[ -n "$settings_snapshot" && -d "$settings_snapshot" ]]; then
        if [[ "$settings_restored" == true ]]; then
            rm -rf -- "$settings_snapshot"
        else
            echo "Previous installation settings were preserved at $settings_snapshot." >&2
        fi
    fi
    exit "$status"
}
trap cleanup_install EXIT
if [[ -e "$home_dir/.current-release" || -L "$home_dir/.current-release" ]]; then
    if [[ ! -f "$home_dir/.current-release" || -L "$home_dir/.current-release" ]]; then
        echo 'Installed release marker is invalid.' >&2
        exit 2
    fi
    previous_version="$(cat -- "$home_dir/.current-release")"
    if [[ ! "$previous_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
        echo 'Installed release marker is invalid.' >&2
        exit 2
    fi
    previous_release="$releases/$previous_version"
    if [[ -L "$previous_release" || ! -d "$previous_release" ||
          ! -f "$previous_release/.release-revision" ]]; then
        echo 'Previous release files are unavailable.' >&2
        exit 2
    fi
    if [[ "$previous_version" == "$version" ]]; then
        previous_snapshot="$(mktemp -d "$releases/.previous-release.XXXXXXXX")"
        cp -a -- "$previous_release/." "$previous_snapshot/"
        previous_release="$previous_snapshot"
    fi
    previous_revision="$(cat -- "$previous_release/.release-revision")"
    if [[ ! "$previous_revision" =~ ^[0-9a-f]{40}$ ]]; then
        echo 'Previous release revision is invalid.' >&2
        exit 2
    fi
    previous_base_ref=ctf-agent-local:latest
    if [[ -f "$previous_release/.image-ref" && ! -L "$previous_release/.image-ref" ]]; then
        previous_base_ref="$(cat -- "$previous_release/.image-ref")"
        if [[ ! "$previous_base_ref" =~ ^ghcr\.io/udonsari0101/ctf-agent-public@sha256:[0-9a-f]{64}$ ]]; then
            echo 'Previous public image reference is invalid.' >&2
            exit 2
        fi
    fi
    previous_base_id="$(docker image inspect --format '{{.Id}}' "$previous_base_ref")"
    if [[ ! "$previous_base_id" =~ ^sha256:[0-9a-f]{64}$ ||
          "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$previous_base_id")" != "$previous_revision" ||
          "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$previous_base_id")" != 'https://github.com/udonsari0101/CTF_Agent' ]]; then
        echo 'Previous public image identity could not be verified.' >&2
        exit 2
    fi
    if [[ -f "$previous_release/deploy/local_runtime.py" ]]; then
        previous_runtime_id="$(python3 "$previous_release/deploy/local_runtime.py" select)"
        [[ "$previous_runtime_id" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 2
    fi
fi
if [[ ! -d "$target" ]]; then
    staging="$(mktemp -d "$releases/.staging.XXXXXXXX")"
    cp -R -- "$bundle_root/app/." "$staging/"
    mkdir -p -- "$staging/installer"
    cp -- "$bundle_root/installer/start.sh" "$bundle_root/installer/uninstall.py" "$staging/installer/"
    printf '%s\n' "$revision" > "$staging/.release-revision"
    mv -- "$staging" "$target"
    staging=""
elif [[ "$(cat -- "$target/.release-revision" 2>/dev/null || true)" != "$revision" ]]; then
    echo 'An installed release with this version has different contents.' >&2
    exit 2
fi

# Refresh only the reviewed local runtime overlay when repairing the same
# release. Application data and the verified public base image stay separate.
for name in Dockerfile.local-runtime compose.local.yaml ctf_agent/solver_worker.py \
    deploy/local_runtime.py deploy/local-compose.py deploy/local-seccomp.json \
    deploy/local-seccomp.README.md deploy/moby-profiles-LICENSE; do
    install -D -m 0644 "$bundle_root/app/$name" "$target/$name"
done

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
if [[ -n "$database_mount" ]]; then
    # Docker Desktop can restart containers before a Windows login task
    # reattaches the VHD. Only the verified launcher may start this stack.
    export CTF_LOCAL_RESTART_POLICY=no
fi
export CTF_LOCAL_DATA="${CTF_LOCAL_DATA:-$home_dir/ctf_agent_data}"
export CTF_LOCAL_DATABASE="$database_path"
export CTF_LOCAL_FS_DATA="${CTF_LOCAL_FS_DATA:-$home_dir/ctf_agent_data}"
export CTF_LOCAL_FS_DATABASE="$database_fs_path"
export CTF_LOCAL_DB_MOUNT="$database_mount"
export CTF_RELEASE_SHA="$revision"
export CTF_RELEASE_VERSION="$version"
cd -- "$target"
image_repository=ghcr.io/udonsari0101/ctf-agent-public
image_tag="$image_repository:$revision"
# Resolve the immutable registry digest before pulling. This is the same
# release image used by the server, including its CTF toolchain layers.
image_digest="$(public_docker manifest inspect --verbose "$image_tag" | python3 -c '
import json, re, sys
manifest = json.load(sys.stdin)
descriptor = manifest.get("Descriptor") if isinstance(manifest, dict) else None
digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("Published release image digest is invalid")
print(digest)
')"
image_ref="$image_repository@$image_digest"
public_docker pull "$image_ref"
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
export CTF_LOCAL_RUNTIME_IMAGE="$(python3 deploy/local_runtime.py build)"
# Verify that Docker sees the live installed database before draining work or
# stopping the existing service. Docker Desktop can retain a stale bind after
# WSL remounts an external VHD, even when its Mount.Source string is correct.
python3 deploy/local-compose.py preflight
manage_storage_control() {
    docker run --rm -i --network none --user 0:0 --entrypoint python \
        -v "$CTF_LOCAL_FS_DATA:/data" "$image_ref" - \
        "$1" "$CTF_LOCAL_UID" "$CTF_LOCAL_GID" "${2:-}" \
        < "$bundle_root/installer/storage_control.py"
}
# The installed web coordinator stops claiming queued work while this file
# exists. Wait for every claimed solve to finish before Compose recreates its
# worker; a timed-out update leaves the current workers running.
drain_file="$CTF_LOCAL_FS_DATA/deployment-drain"
if [[ -L "$CTF_LOCAL_FS_DATA" ]]; then
    echo 'The data path must not be a symlink.' >&2
    exit 1
fi
mkdir -p -- "$CTF_LOCAL_FS_DATA"
# init-storage intentionally makes /data root-owned 0750. Use a narrowly
# scoped helper for these control files both before and after Compose runs.
drain_token="$(manage_storage_control reserve)"
if [[ -n "$database_mount" && "${CTF_UPDATE_IN_PROGRESS:-false}" != true ]]; then
    update_control="$home_dir/ctf_agent_data/update-control"
    if [[ -e "$update_control/request.json" || -L "$update_control/request.json" ||
          -e "$update_control/running.json" || -L "$update_control/running.json" ]]; then
        echo 'A site update is queued or running; finish it before switching update controllers.' >&2
        exit 1
    fi
fi
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
wait_service_healthy() {
    local expected_image="$1" deadline=$((SECONDS + $2)) health current_image
    while (( SECONDS < deadline )); do
        health="$(docker inspect --format '{{.State.Health.Status}}' ctf_agent_local 2>/dev/null || true)"
        current_image="$(docker inspect --format '{{.Image}}' ctf_agent_local 2>/dev/null || true)"
        if [[ "$health" == healthy && "$current_image" == "$expected_image" ]]; then return 0; fi
        if [[ "$health" == unhealthy ]]; then return 1; fi
        sleep 5
    done
    return 1
}
restore_previous_service() {
    [[ -n "$previous_release" && -n "$previous_base_id" ]] || return 1
    # The attempted install may have changed auth and auto-start. Recover
    # these values from the restored previous configuration, never from the
    # failed install's exported environment.
    local prior_options prior_auth prior_restart
    prior_options="$(python3 - "$home_dir/.local-config.json" "$database_mount" <<'PY'
import json, sys
from pathlib import Path
path, expected_mount = Path(sys.argv[1]), sys.argv[2]
if path.is_symlink() or not path.is_file():
    raise SystemExit('Previous local settings are unavailable')
settings = json.loads(path.read_text(encoding='utf-8'))
mode, auto = settings.get('auth_mode'), settings.get('auto_start')
if mode not in {'password', 'nologin'} or type(auto) is not bool:
    raise SystemExit('Previous local settings are invalid')
if settings.get('database_mount', '') != expected_mount:
    raise SystemExit('Previous database mount changed')
print(mode, 'no' if expected_mount or not auto else 'unless-stopped')
PY
)" || return 1
    read -r prior_auth prior_restart <<< "$prior_options"
    [[ "$prior_auth" == password || "$prior_auth" == nologin ]] || return 1
    [[ "$prior_restart" == no || "$prior_restart" == unless-stopped ]] || return 1
    docker image tag "$previous_base_id" ctf-agent-local:latest || return 1
    (
        cd -- "$previous_release"
        CTF_LOCAL_RUNTIME_IMAGE="$previous_runtime_id" \
        CTF_AUTH_MODE="$prior_auth" CTF_LOCAL_AUTH_MODE="$prior_auth" \
        CTF_LOCAL_RESTART_POLICY="$prior_restart" \
        CTF_RELEASE_SHA="$previous_revision" CTF_RELEASE_VERSION="$previous_version" \
            python3 deploy/local-compose.py up -d --no-build --force-recreate
    ) || return 1
    local previous_image="${previous_runtime_id:-$previous_base_id}"
    if ! wait_service_healthy "$previous_image" 180; then return 1; fi
    echo "Previous CTF Agent release $previous_version restored and ready." >&2
}
# Drain old claims first, then stop the old coordinators before removing this
# install's marker and starting the new stack.
rollout_started=true
docker compose -f compose.local.yaml stop web solver-autoscaler
if [[ -n "$database_mount" && "${CTF_UPDATE_IN_PROGRESS:-false}" != true ]]; then
    update_control="$home_dir/ctf_agent_data/update-control"
    # Web is now stopped, so no new request can be queued. A pending or
    # running request must finish before replacing the old Docker updater.
    if [[ -e "$update_control/request.json" || -L "$update_control/request.json" ||
          -e "$update_control/running.json" || -L "$update_control/running.json" ]]; then
        echo 'A site update is queued or running; finish it before switching update controllers.' >&2
        exit 1
    fi
    if docker container inspect ctf_agent_local_updater >/dev/null 2>&1; then
        docker stop ctf_agent_local_updater >/dev/null
    fi
    manage_storage_control handoff >/dev/null
fi
docker image tag "$image_ref" ctf-agent-local:latest
manage_storage_control release "$drain_token" >/dev/null
drain_token=""
python3 deploy/local-compose.py up -d --no-build
if [[ "${CTF_UPDATE_IN_PROGRESS:-false}" != true ]]; then
    if ! wait_service_healthy "$CTF_LOCAL_RUNTIME_IMAGE" 180; then
        echo 'The new solver did not pass /readyz before the installation deadline.' >&2
        exit 1
    fi
fi
if [[ -z "$previous_version" ]]; then
    # A healthy web on Docker Desktop can still be bound to a stale shadow of
    # an external VHD. Verify the new SQLite on the WSL host and its live bind
    # before selecting this release as the installed version.
    python3 deploy/local-compose.py verify-fresh-install
fi
# Web updates perform their own readiness check and rollback. Manual installs
# keep the previous release available through the remaining launcher and
# updater setup, which can still fail after the web service becomes healthy.
settings_snapshot="$(mktemp -d "$home_dir/.previous-settings.XXXXXXXX")"
for name in .current-release .local-config.json .updater-image; do
    path="$home_dir/$name"
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || { echo 'Previous installation settings are invalid.' >&2; exit 2; }
        cp -p -- "$path" "$settings_snapshot/${name#.}"
    fi
done
if [[ -e "$home_dir/.launcher" || -L "$home_dir/.launcher" ]]; then
    [[ -d "$home_dir/.launcher" && ! -L "$home_dir/.launcher" ]] || { echo 'Previous launcher is invalid.' >&2; exit 2; }
    for name in start.sh uninstall.py; do
        path="$home_dir/.launcher/$name"
        if [[ -e "$path" || -L "$path" ]]; then
            [[ -f "$path" && ! -L "$path" ]] || { echo 'Previous launcher file is invalid.' >&2; exit 2; }
            cp -p -- "$path" "$settings_snapshot/launcher-$name"
        fi
    done
fi
install -d -m 0750 -o "$CTF_LOCAL_UID" -g "$CTF_LOCAL_GID" "$home_dir/.launcher"
for name in start.sh uninstall.py; do
    cp -- "$bundle_root/installer/$name" "$home_dir/.launcher/$name"
    chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$home_dir/.launcher/$name"
    chmod 0644 "$home_dir/.launcher/$name"
done
local_config_temp="$(mktemp "$home_dir/.local-config.XXXXXXXX")"
python3 - "$local_config_temp" "$CTF_AUTH_MODE" "${CTF_LOCAL_AUTOSTART:-true}" \
    "$database_fs_path" "$database_mount" "$database_volume_id" <<'PY'
import json, sys
target, auth_mode, auto_start, database_path, database_mount, volume_id = sys.argv[1:]
value = {"auth_mode": auth_mode, "auto_start": auto_start == "true",
         "database_path": database_path, "database_mount": database_mount,
         "database_volume_id": volume_id}
with open(target, "w", encoding="utf-8") as output:
    json.dump(value, output, separators=(",", ":"))
    output.write("\n")
PY
chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$local_config_temp"
mv -f -- "$local_config_temp" "$home_dir/.local-config.json"
if [[ "${CTF_UPDATE_IN_PROGRESS:-false}" != true ]]; then
    current_temp="$(mktemp "$home_dir/.current-release.XXXXXXXX")"
    printf '%s\n' "$version" > "$current_temp"
    chown "$CTF_LOCAL_UID":"$CTF_LOCAL_GID" "$current_temp"
    mv -f -- "$current_temp" "$home_dir/.current-release"
fi
if [[ "${CTF_UPDATE_IN_PROGRESS:-false}" != true && -z "$database_mount" ]]; then
    updater_candidate="ctf_agent_local_updater_candidate_$$"
    if docker container inspect ctf_agent_local_updater_previous >/dev/null 2>&1 ||
       docker container inspect "$updater_candidate" >/dev/null 2>&1; then
        echo 'An earlier update-controller replacement needs inspection.' >&2
        exit 1
    fi
    if docker container inspect ctf_agent_local_updater >/dev/null 2>&1; then
        updater_old_exists=true
        updater_old_running="$(docker inspect --format '{{.State.Running}}' ctf_agent_local_updater)"
        updater_old_image="$(docker inspect --format '{{.Image}}' ctf_agent_local_updater)"
        [[ "$updater_old_image" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
    fi
    update_control="$home_dir/ctf_agent_data/update-control"
    if [[ -e "$update_control/request.json" || -e "$update_control/running.json" ]]; then
        echo 'A site update is queued or running; finish it before reinstalling.' >&2
        exit 1
    fi
    updater_fingerprint="$(sha256sum Dockerfile.updater ctf_agent/release_updates.py | sha256sum | cut -d ' ' -f 1)"
    updater_stamp="$home_dir/.updater-image"
    if ! docker image inspect ctf-agent-updater:local >/dev/null 2>&1 ||
       [[ "$(cat -- "$updater_stamp" 2>/dev/null || true)" != "$updater_fingerprint" ]]; then
        public_docker build --file Dockerfile.updater --tag ctf-agent-updater:local .
        printf '%s\n' "$updater_fingerprint" > "$updater_stamp"
    fi
    if [[ "$updater_old_exists" == true && "$updater_old_running" == true ]]; then
        docker stop ctf_agent_local_updater >/dev/null
    fi
    status_file="$home_dir/ctf_agent_data/update-control/status.json"
    status_before_ns="$(python3 - "$status_file" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
print(path.stat().st_mtime_ns if path.exists() else 0)
PY
)"
    updater_mount=()
    if [[ -n "$database_mount" ]]; then
        updater_mount=(-v "$database_mount:$database_mount")
    fi
    updater_candidate_started=true
    docker run -d --name "$updater_candidate" --restart "$CTF_LOCAL_RESTART_POLICY" \
        --memory 1g --cpus 1 --security-opt no-new-privileges \
        -e "CTF_LOCAL_HOME=$home_dir" -e "CTF_LOCAL_UID=$CTF_LOCAL_UID" -e "CTF_LOCAL_GID=$CTF_LOCAL_GID" \
        -e "CTF_LOCAL_DB_MOUNT=$database_mount" \
        -v "$home_dir:$home_dir" "${updater_mount[@]}" -v /var/run/docker.sock:/var/run/docker.sock \
        ctf-agent-updater:local >/dev/null
    updater_ready=false
    for attempt in {1..10}; do
        running="$(docker inspect --format '{{.State.Running}}' "$updater_candidate" 2>/dev/null || true)"
        if [[ "$running" != true ]]; then
            echo 'The update controller stopped before becoming ready.' >&2
            exit 1
        fi
        if python3 - "$status_file" "$status_before_ns" <<'PY'
import json, sys, time
from pathlib import Path
path = Path(sys.argv[1])
try:
    fresh = path.stat().st_mtime_ns > int(sys.argv[2])
    value = json.loads(path.read_text(encoding="utf-8")) if fresh else {}
    healthy = time.time() - float(value.get("updated_at", 0)) < 10
except (OSError, ValueError, TypeError):
    healthy = False
raise SystemExit(0 if healthy else 1)
PY
        then
            updater_ready=true
            break
        fi
        sleep 2
    done
    if [[ "$updater_ready" != true ]]; then
        echo 'The update controller did not become ready.' >&2
        exit 1
    fi
    if [[ "$updater_old_exists" == true ]]; then
        docker rename ctf_agent_local_updater ctf_agent_local_updater_previous
        updater_old_renamed=true
    fi
    docker rename "$updater_candidate" ctf_agent_local_updater
    updater_promoted=true
    if [[ "$(docker inspect --format '{{.State.Running}}' ctf_agent_local_updater)" != true ]]; then
        echo 'The replacement update controller is not running.' >&2
        exit 1
    fi
    if [[ "$updater_old_renamed" == true ]]; then
        docker rm ctf_agent_local_updater_previous >/dev/null
        updater_old_renamed=false
    fi
fi
if [[ -n "$database_mount" && "${CTF_UPDATE_IN_PROGRESS:-false}" != true ]]; then
    python3 "$target/ctf_agent/release_updates.py" --prepare-host-worker
    status_file="$home_dir/ctf_agent_data/update-control/status.json"
    status_before_ns="$(python3 - "$status_file" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
print(path.stat().st_mtime_ns if path.exists() else 0)
PY
)"
    nohup python3 "$target/ctf_agent/release_updates.py" --host-worker \
        </dev/null >/dev/null 2>&1 &
    host_updater_ready=false
    for attempt in {1..6}; do
        if python3 - "$status_file" "$status_before_ns" <<'PY'
import json, sys, time
from pathlib import Path
path = Path(sys.argv[1])
try:
    fresh = path.stat().st_mtime_ns > int(sys.argv[2])
    value = json.loads(path.read_text(encoding="utf-8")) if fresh else {}
    healthy = time.time() - float(value.get("updated_at", 0)) < 10
except (OSError, ValueError, TypeError):
    healthy = False
raise SystemExit(0 if healthy else 1)
PY
        then
            host_updater_ready=true
            break
        fi
        sleep 2
    done
    [[ "$host_updater_ready" == true ]] || {
        echo 'The host update controller did not become ready.' >&2; exit 1;
    }
fi
new_ready=true
printf '\nCTF Agent %s files and services configured; solver readiness requires /readyz HTTP 200.\n' "$version"
printf 'Data: %s\n' "$CTF_LOCAL_DATA"
