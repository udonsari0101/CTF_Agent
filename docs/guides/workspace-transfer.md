# Move a workspace or challenge between installations

Use **Export ZIP** on the source and **Import ZIP** on the destination for the
portable path. Version 2 ZIPs contain the workspace or one challenge, notes,
flags, write-ups, attachment files, and solver job history (events, subagent
records, context readings, elapsed times, and user guidance). Imported jobs
are marked read-only; a running source job becomes a stopped historical job at
the destination. The ZIP excludes account credentials, browser sessions, CTFd
credentials, Telegram settings, live provider sessions, retry checkpoints,
worker state, and notification delivery hooks. Workspace-level files staged for
future challenges are also excluded until they are attached to a challenge;
attach them before exporting if they need to move with the workspace. Version 1
ZIPs remain importable.
Challenge text, attachments, notes, and solver logs can contain secrets that
you entered or observed yourself, so handle the ZIP as private data. Challenge
imports require an existing destination workspace; workspace imports create a
new workspace. Retrying an import with the same upload ID returns the previous
result without duplicating history.

**Direct transfer** sends the same ZIP between two installations. On the
destination, create an invitation for a new workspace or one challenge in a
chosen workspace, then copy its URL and token to the source's **Send directly**
dialog. The source creates a private snapshot and proposes its exact ZIP size,
checksum, and estimated unpacked attachment size. The destination owner sees
the sizes and must explicitly approve before any ZIP bytes are sent. Approval
checks available disk space; rejection cancels the invitation. The ZIP then
travels in resumable 8 MiB chunks over HTTPS. The token authorizes only that
owner's invitation, scope, destination workspace, and one ZIP checksum. An
unapproved invitation expires after one hour; approval extends the transfer
window to 24 hours. The source sends no local account cookie or provider
credential. The destination owner can revoke an active invitation before
import completes. Remote endpoint fields are omitted by default; include
them only when explicitly selected.

The destination needs a public, reachable HTTPS origin with a certificate the
source trusts. Set `CTF_PUBLIC_ORIGIN=https://your-host.example` in a server
deployment. In the local Compose template, set `CTF_LOCAL_ORIGIN` to the
equivalent HTTPS origin; Compose passes it to the container as
`CTF_PUBLIC_ORIGIN`. The usual Windows/local setup defaults to
`http://127.0.0.1:5050`, so it cannot **receive** direct transfers until it is
published through HTTPS and that setting is persisted in its launch
environment. A local installation can still **send** to a public HTTPS
destination. Direct transfer rejects private or loopback destination addresses,
HTTP, redirects, invalid TLS certificates, and proxy settings. Source
operators can restrict public destination hostnames with
`CTF_DIRECT_TRANSFER_ALLOW_HOSTS` and `CTF_DIRECT_TRANSFER_DENY_HOSTS`
(comma-separated exact names or `*.example.com` suffixes).

If the destination is protected by Cloudflare Access or another edge login,
the direct sender cannot pass that separate edge authentication. Use manual ZIP
export/import in that setup. Manual ZIP is also the route for local-only or
private-network destinations.

The source starts a background job and shows progress. If it fails or its
process restarts, submit the **same** invitation URL and token again: the
source keeps the original private ZIP for up to seven days, and the destination
continues from its recorded byte offset. The source stores only a token hash,
never the raw token. A completed send removes the source ZIP. Pending snapshots
are limited to two per owner, and cleanup skips an active send. There is no
selectable fixed ZIP size: actual free space and concurrent storage reservations
determine whether export and import can proceed. Local uploads preserve at
least 5 GiB free. If the original snapshot expires or is missing, create a new
destination invitation.
