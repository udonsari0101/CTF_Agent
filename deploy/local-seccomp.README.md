# Local solver namespace profile

The local Docker Desktop solver needs nested unprivileged namespaces for
Codex 0.164.0's bubblewrap sandbox. The normal Docker profile blocks these.
`local-seccomp.json` retains Moby's default-deny profile and its other rules,
and additionally permits `clone`, `unshare`, `setns`, `mount`, `umount2`, and
`pivot_root`. Kernel capability checks still apply. The solver remains
non-root, `cap_drop: ALL`, `no-new-privileges`, and read-only at its root.
This profile is used only by the solver services, not the Docker daemon.

Upstream: https://github.com/moby/profiles/tree/4b8214fc4971e06172938a1f1554ccff6647ee80/seccomp

Original `default.json` SHA256:
`6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6`.

Changes: appended one SCMP_ACT_ALLOW rule containing the six names above;
JSON formatting changed. All original rules remain intact. The Apache 2.0
license is included in `moby-profiles-LICENSE`.

Codex command permissions separately restrict writes to the current job
workspace, deny `/dev/shm`, protect the worker/app-server process namespace,
and select an offline profile for jobs with network disabled. The original
startup canary remains the readiness gate; policy installation alone does
not assert that the worker is safe or ready.
