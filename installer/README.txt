CTF Agent - Windows local installation

1. Extract the entire release ZIP to a local folder.
2. Run Install.cmd. Choose a WSL 2 distribution and press Enter at the data
   path prompt for the usual Linux folder.
   The installer can offer to install WSL or Docker Desktop if needed.
   To put only the database in a Windows folder, paste a path on any fixed
   local drive (C:, D:, E:, including the WSL distribution's drive), such as
   D:\CTF-Agent\data at the data path prompt. The installer stores
   its ext4 VHDX at
   D:\CTF-Agent\data\ctf-agent-db.vhdx and leaves challenge files
   at the usual WSL path. Existing databases are not migrated automatically.
   Choose whether to start the service at Windows sign-in and require login.
3. Open http://127.0.0.1:5050. If you chose password login, create the first
   administrator account. The no-login mode skips this step.
4. Connect a Codex or Claude Code account in Agents.

Requirements: x64 Windows, WSL 2, Docker Desktop with its WSL 2 engine and
integration enabled for the selected distribution, and internet access.
Installation preserves 5 GiB of free space on the WSL application filesystem
and each Windows backing drive. It plans another 1 GiB for application
staging, 10 GiB for a cold Docker image pull (2 GiB when the exact image is
cached), and 1 GiB when creating or growing a separate database VHDX. When
these files are on the same Windows drive, the installer adds their planned
writes before checking that drive; on separate drives it checks each one.
Docker Desktop's image VHDX location is read from its settings. If the
location cannot be detected, installation stops before changing service
data. Set CTF_AGENT_DOCKER_DATA_ROOT to that disk-image folder and rerun.
During use, application uploads share a 5 GiB WSL filesystem floor and
reserve large and concurrent writes; managed solver archive expansion uses
the same 5 GiB default floor. Windows backing-drive growth after
installation must still be monitored in Windows, especially for a separate
database VHDX; the container cannot read that host drive's free space.
Start.cmd warns when a Windows backing volume falls below 5 GiB but still
starts an existing installation. New uploads or solver writes may be refused.

If installed WSL distributions are listed but readiness checks fail, read the
reason shown for each one. Retry Install.cmd as administrator under the same
Windows account that owns those distributions. WSL registrations are per-user;
do not install another Ubuntu just because a readiness check failed.

To upgrade, extract a newer release and run its Install.cmd. The selected
data directory and database are preserved. The installer remembers the WSL
distribution and data path under your Windows user profile.
When an update changes the Windows Start.cmd or Uninstall.cmd launchers, run
the newer Install.cmd once to refresh their PowerShell files. A web update
updates the Linux application stack but cannot reliably copy files into your
Windows app data folder when WSL Windows interoperability is unavailable.

To browse challenge files in Windows Explorer, open the data directory via
\\wsl.localhost\<distribution>\<Linux path>\ctf_agent_data\workspace_files
or use explorer.exe from a WSL terminal. Keep files inside the WSL Linux
filesystem for Docker performance.

The ZIP contains source and an installer. The installer pulls the public
release image, including the CTF toolchain, by verified GHCR digest. A small
local worker-policy overlay and update controller are built from that verified
image; the toolchain is not rebuilt. The public base identity and local image
identity are checked again when the service starts. Cached images may remain
after uninstall.

Installation and Start.cmd check /readyz before reporting the service ready.
If the solver cannot start, the launcher reports its reason while preserving
the selected data, database and installation settings.
When replacing a running release, the installer attempts to restore the
previous release if the new Compose stack fails to start or pass readiness.
If a later launcher or update-controller setup step fails after the web
service is ready, rerun Install.cmd to finish that step; it does not imply
the running service was rolled back.

Start.cmd and Uninstall.cmd are also copied to your local Windows app data
folder under CTF Agent. Start.cmd starts the installed service even when
automatic startup is off. Uninstall.cmd removes only its containers, image
tags and release files. It keeps data, the database, WSL and Docker Desktop.
