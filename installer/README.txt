CTF Agent - Windows local installation

1. Extract the entire release ZIP to a local folder.
2. Run Install.cmd. Choose a WSL 2 distribution and press Enter at the data
   path prompt for the usual Linux folder.
   The installer can offer to install WSL or Docker Desktop if needed.
   To put only the database in a Windows folder, paste a path on any fixed
   local drive (C:, D:, E:, including the WSL distribution's drive), such as
   D:\Develop\ctf_agent\data at the data path prompt. The installer stores
   its ext4 VHDX at
   D:\Develop\ctf_agent\data\ctf-agent-db.vhdx and leaves challenge files
   at the usual WSL path. Existing databases are not migrated automatically.
   Choose whether to start the service at Windows sign-in and require login.
3. Open http://127.0.0.1:5050 and create the first administrator account.
4. Connect a Codex or Claude Code account in Agents.

Requirements: x64 Windows, WSL 2, Docker Desktop with its WSL 2 engine and
integration enabled for the selected distribution, internet access, and at
least 15 GB of available space in WSL and on its backing Windows volume.

If installed WSL distributions are listed but readiness checks fail, read the
reason shown for each one. Retry Install.cmd as administrator under the same
Windows account that owns those distributions. WSL registrations are per-user;
do not install another Ubuntu just because a readiness check failed.

To upgrade, extract a newer release and run its Install.cmd. The selected
data directory and database are preserved. The installer remembers the WSL
distribution and data path under your Windows user profile.

To browse challenge files in Windows Explorer, open the data directory via
\\wsl.localhost\<distribution>\<Linux path>\ctf_agent_data\workspace_files
or use explorer.exe from a WSL terminal. Keep files inside the WSL Linux
filesystem for Docker performance.

The ZIP contains source and an installer. The installer pulls the public
release image, including the CTF toolchain, by verified GHCR digest. It does
not build the application locally. The small update controller is built
locally. A shared public image cache may remain after uninstall.

Start.cmd and Uninstall.cmd are also copied to your local Windows app data
folder under CTF Agent. Start.cmd starts the installed service even when
automatic startup is off. Uninstall.cmd removes only its containers, image
tags and release files. It keeps data, the database, WSL and Docker Desktop.
