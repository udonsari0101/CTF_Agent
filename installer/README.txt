CTF Agent - Windows local installation

1. Extract the entire release ZIP to a local folder.
2. Run Install.cmd. Choose a WSL 2 distribution and a Linux data folder.
   The installer can offer to install WSL or Docker Desktop if needed.
3. Open http://127.0.0.1:5050 and create the first administrator account.
4. Connect a Codex or Claude Code account in Agents.

Requirements: x64 Windows, WSL 2, Docker Desktop with its WSL 2 engine and
integration enabled for the selected distribution, internet access, and at
least 15 GB of available space in WSL and on its backing Windows volume.

To upgrade, extract a newer release and run its Install.cmd. The selected
data directory and database are preserved. The installer remembers the WSL
distribution and data path under your Windows user profile.

To browse challenge files in Windows Explorer, open the data directory via
\\wsl.localhost\<distribution>\<Linux path>\ctf_agent_data\workspace_files
or use explorer.exe from a WSL terminal. Keep files inside the WSL Linux
filesystem for Docker performance.

The ZIP contains source and an installer. The first install builds the CTF
toolchain and application images locally. Subsequent upgrades reuse an
unchanged toolchain image.
