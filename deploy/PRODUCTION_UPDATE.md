# Server update controller

The site Update button can upgrade an existing registry based server installation. The controller uses the public GitHub release tag and the public GHCR image built from that tagged commit. The Docker host only pulls an immutable image digest and starts it with `docker compose up -d --no-build`; it does not build an image.

## Existing server layout

This integration is for an installation that already has:

- A host data directory bind mounted into the web container at `/data`. The controller creates `update-control` inside that host directory; the web process uses UID 10001 to queue requests.
- A `releases` directory inside that same host data directory, owned by root, with `current` containing the running 40-character Git commit SHA.
- `releases/<SHA>/release.sh`, `compose.yaml`, and `image-ref`. The release script must serialize Docker operations with the same global `flock`, drain active solver jobs, check health, and roll back on failure. The included `remote-rollout.sh` invokes that script.
- A running `ctf_agent` container with `CTF_RELEASE_SHA` set to the commit SHA and `docker` available on the host. The currently configured image repository must publish SHA tags.

The release archive includes the controller and rollout script at `app/deploy/` and `app/.github/scripts/`. After extracting it, install the controller once as root:

```sh
sh app/deploy/bootstrap-production-update.sh \
  /absolute/data/root/releases \
  github-owner/repository \
  ghcr.io/github-owner/image \
  v0.4.2
```

Set the final argument to the current installed version. This one-time migration records the running SHA and version. Subsequent updates verify the latest published release tag, resolve that tag to its commit SHA, and verify the SHA tagged registry manifest before invoking the existing rollout. After a healthy deployment, the controller refreshes its own files from the running image and restarts via systemd.

The install creates `/etc/ctf-agent/production-update.json`, `/usr/local/libexec/ctf-agent-production-update.py`, `/usr/local/libexec/ctf-agent-remote-rollout.sh`, and `ctf-agent-production-update.service`. Review `systemctl status ctf-agent-production-update.service` before using the Update button. The site UI can refresh the GitHub release check immediately; a failed or incomplete helper appears as unavailable.

The controller is separate from the Windows local installer. The Windows archive identifies the same release commit and pulls the identical public GHCR application image by digest. It keeps its local Compose settings and update worker; neither updater requires a GitHub Actions deployment credential in the web service. A source checkout may still build locally when explicitly started with `--build`.
