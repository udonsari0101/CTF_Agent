#!/bin/sh
# This runs on an operator-configured Docker host. Paths and credentials arrive
# from repository secrets; no host-specific configuration belongs in the image.
set -eu
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH
export PATH

[ "$#" -eq 3 ] || { echo 'Expected revision, image digest, and release root.' >&2; exit 1; }
revision=$1
image_ref=$2
release_root=$3
case "$revision" in *[!0-9a-f]*|'') exit 1 ;; esac
[ "${#revision}" -eq 40 ] || exit 1
case "$image_ref" in ghcr.io/udonsari0101/ctf-agent-public@sha256:*) ;; *) exit 1 ;; esac
digest=${image_ref##*@sha256:}
case "$digest" in *[!0-9a-f]*|'') exit 1 ;; esac
[ "${#digest}" -eq 64 ] || exit 1
case "$release_root" in /*) ;; *) exit 1 ;; esac
[ -d "$release_root" ] && [ ! -L "$release_root" ] || exit 1
[ "$(readlink -f "$release_root")" = "$release_root" ] || exit 1

current_file=$release_root/current
[ -f "$current_file" ] && [ ! -L "$current_file" ] || exit 1
current=$(cat "$current_file")
case "$current" in *[!0-9a-f]*|'') exit 1 ;; esac
[ "${#current}" -eq 40 ] || exit 1
if [ "$current" = "$revision" ]; then
    running_image=$(docker inspect --format '{{.Config.Image}}' ctf_agent)
    health=$(docker inspect --format '{{.State.Health.Status}}' ctf_agent)
    [ "$running_image" = "$image_ref" ] && [ "$health" = healthy ] || exit 1
    echo "Already healthy: $revision"
    exit 0
fi

source_dir=$release_root/$current
target_dir=$release_root/$revision
[ -f "$source_dir/release.sh" ] && [ ! -L "$source_dir/release.sh" ] || exit 1
if [ ! -e "$target_dir" ]; then
    mkdir -m 0750 "$target_dir"
    cp -a "$source_dir"/. "$target_dir"/
fi
[ -d "$target_dir" ] && [ ! -L "$target_dir" ] || exit 1
[ -f "$target_dir/release.sh" ] && [ ! -L "$target_dir/release.sh" ] || exit 1
grep -q 'ctf-agent-public@sha256' "$target_dir/release.sh" || {
    echo 'The host release script does not support the public image registry.' >&2
    exit 1
}
if [ -f "$target_dir/image-ref" ] &&
   [ "$(cat "$target_dir/image-ref")" != "$image_ref" ] &&
   [ "$(cat "$target_dir/image-ref")" != "$(cat "$source_dir/image-ref")" ]; then
    echo 'The existing release directory has a different image digest.' >&2
    exit 1
fi
umask 027
printf '%s\n' "$image_ref" > "$target_dir/.image-ref.tmp"
chmod 0640 "$target_dir/.image-ref.tmp"
mv "$target_dir/.image-ref.tmp" "$target_dir/image-ref"
sh -n "$target_dir/release.sh"
CTF_COMPATIBILITY_PROBE_ONLY=1 sh "$target_dir/release.sh" "$revision"
CTF_IMAGE=$image_ref CTF_RELEASE_SHA=$revision docker compose -f "$target_dir/compose.yaml" config --quiet
[ "$(cat "$current_file")" = "$current" ] || {
    echo 'The active release changed during preparation.' >&2
    exit 1
}
sh "$target_dir/release.sh" "$revision"
