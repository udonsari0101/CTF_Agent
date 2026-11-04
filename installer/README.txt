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
3. Open http://127.0.0.1:5050 and create the first administrator account.
4. Connect a Codex or Claude Code account in Agents.

Requirements: x64 Windows, WSL 2, Docker Desktop with its WSL 2 engine and
integration enabled for the selected distribution, and internet access.
Installation leaves at least 5 GiB free on the WSL data filesystem and its
Windows backing volume. Before pulling a new image it requires an estimated
10 GiB of extra work space (15 GiB total); if that exact release image is
cached, it requires 2 GiB extra (7 GiB total). A separate database drive
needs at least 5 GiB free. Docker Desktop's image VHDX is checked separately,
including a disk-image location changed in Docker Desktop settings. If its
location cannot be detected, the installer stops before changing service
data. Set CTF_AGENT_DOCKER_DATA_ROOT to that disk-image folder and rerun.

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
