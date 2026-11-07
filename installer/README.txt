CTF Agent - Windows local installation

1. Extract the entire release ZIP to a local folder.
2. Run Install.cmd. Select a WSL 2 distribution and whether to use or install
   Docker Desktop. Both questions use the recommended answer after 30 seconds
   without input, so an unattended installation continues. The installer
   prepares WSL, enables Docker Desktop integration, creates the containers
   and opens the local site in your browser.
3. If you kept password login, create the first administrator account at
   http://127.0.0.1:5050. The no-login mode skips this step.
4. Connect a Codex or Claude Code account in Agents.

Install.cmd accepts these optional arguments:
  -Distribution <name>    Use this WSL distribution, installing a named Ubuntu
                          if missing. Skips the timed WSL selection question.
  -DockerMode <mode>      Existing or Install. Skips the timed Docker question;
                          Install upgrades Docker Desktop if it is present.
  -DataFolder <path>      Linux path for application data.
  -DatabaseFolder <path>  Windows folder, on any fixed local drive, for the
                          database only. The installer stores its ext4 VHDX at
                          <path>\ctf-agent-db.vhdx and leaves challenge files
                          at the usual WSL path. Existing databases are not
                          migrated automatically.
  -ListenAddress <addr>   127.0.0.1 (default) accepts this computer only.
                          0.0.0.0 accepts every address, for port forwarding,
                          and adds a Windows Firewall rule for TCP 5050 after
                          one administrator approval. The choice is remembered.
  -PublicUrl <origins>    One or more comma-separated HTTP(S) origins, such as
                          https://agent.example.com,https://other.example.com.
                          Automatically listens on 0.0.0.0 unless an explicit
                          -ListenAddress is supplied. Origins are remembered.
  -OpenAccess             With -NoLogin, let every browser reaching the service
                          use it without a connection ticket. This is already
                          the default when no-login mode listens on 0.0.0.0.
                          Use -OpenAccess:$false to require one-use links;
                          repeat that switch when reinstalling or upgrading.
  -NoLogin                Do not require an account on this computer.
  -DockerFolder <path>    Move Docker Desktop's disk to this folder.
  -StartAtSignIn          Start the service when you sign in to Windows.
  -Interactive            Also ask for optional folder and login settings.
Rerunning Install.cmd reuses the saved settings of the previous installation.

When password login is enabled on a public address, the installer prints a
first-administrator setup token. Enter it in the first-account form. Keep it
private; the token prevents someone who connects first from claiming the
administrator account. The token is kept across upgrades. Create the first
administrator before inviting other users.

The containers cannot run as root. When the distribution's default Linux user
is root, the installer makes an existing regular user the default, or creates
one named ctfagent. wsl --user root keeps working. A missing home folder is
created for the same reason: Docker Desktop's integration needs it.

With -ListenAddress 0.0.0.0, no-login mode opens directly in every browser by
default. If you explicitly select -OpenAccess:$false, run RemoteLink.cmd in
the CTF Agent app data folder to connect another device. It uses the first
-PublicUrl when configured; otherwise pass a host or full origin. Each link
works once and connects that browser for 30 days. Open access means anyone
who can reach the address can use the service.
Direct HTTP traffic is unencrypted, so use a VPN or TLS proxy over the internet.

Install.cmd stops and restarts Docker Desktop to change its WSL integration
setting. It refuses to do this while containers are running.

Windows may still ask for you in these cases: enabling WSL for the first time
(administrator approval and a restart; installation then continues by itself
after you sign in), installing Docker Desktop (administrator approval and its
license window), and first using a VHDX or logon task from an older release
(one administrator approval).

Requirements: x64 Windows, WSL 2, Docker Desktop with its WSL 2 engine, and
internet access.
Installation preserves 5 GiB of free space on the WSL application filesystem
and each Windows backing drive. It plans another 1 GiB for application
staging, 18 GiB for a cold Docker image pull and local build (10 GiB when the
exact image is cached), and 1 GiB when creating or growing a separate database
VHDX. If Docker Desktop's drive is too full, Install.cmd moves its disk to the
database drive or the fixed NTFS drive with the most room. When
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

If a distribution fails its readiness checks, Install.cmd prints the reason and
tries the next one, and installs a new Ubuntu when none is usable. WSL
registrations are per-user, so run Install.cmd under the Windows account that
owns your distributions. With -Interactive, retry as administrator under that
same account; do not install another Ubuntu just because a check failed.

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
