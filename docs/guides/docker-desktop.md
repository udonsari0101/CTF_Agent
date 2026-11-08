# Windows installation with Docker Desktop

## Release installer

Download and extract the latest [Windows release ZIP](https://github.com/udonsari0101/CTF_Agent/releases/latest), then run `Install.cmd`.

The installer saves its startup and login choices; use `-Interactive` to choose them at installation or pass options as described below. It creates Start.cmd, RemoteLink.cmd, and Uninstall.cmd in the CTF Agent folder under your local Windows app data directory. Click Start.cmd whenever you want to run the service manually. Uninstall.cmd confirms the two retained data paths, then removes only CTF Agent containers, its image tags, and its installed release files. It does not unregister WSL, uninstall Docker Desktop, remove other containers, or delete the selected data and database folders. If Docker is unavailable, removal stops before deleting release files so you can retry after Docker Desktop starts.

The installer checks WSL 2, recommends an installed Linux distribution or offers to install Ubuntu, and checks Docker Desktop and its WSL integration. By default, application data stays in the selected distribution's Linux filesystem at `~/.local/share/ctf-agent`. The installer remembers this location for upgrades.

Installation preserves 5 GiB of free space on the WSL data filesystem and each Windows backing drive. It estimates another 1 GiB for application staging, 18 GiB for an uncached Docker image pull and local build, or 10 GiB when the exact image is cached. A separate database VHDX adds a 1 GiB growth estimate. When these disks share a Windows volume, the installer adds their planned writes before applying the 5 GiB floor; separate volumes are checked independently.

The in-app updater separately reserves up to 150 MiB for the release ZIP and 300 MiB for extraction before the image check. It can measure WSL filesystem capacity but cannot directly verify free space on its Windows backing volume or a custom Docker Desktop disk-image location. During use, uploads and imports reserve large and concurrent writes against the WSL data filesystem. Monitor Windows drive capacity, especially if an external database VHDX expands. `Start.cmd` warns if a backing drive falls below 5 GiB but still starts an existing installation; new uploads or solver writes may then be refused.

### Installer options

`Install.cmd` reuses saved settings and detected defaults. Its WSL and Docker choice prompts proceed with the displayed default after 30 seconds. `-Distribution` and `-DockerMode` skip those prompts; `-Interactive` lets you review the remaining settings as well. For a repeatable installation, supply the required choices on the command line:

```powershell
.\Install.cmd -Distribution Ubuntu-24.04 -DockerMode Existing -DataFolder /home/user/.local/share/ctf-agent -DatabaseFolder D:\CTF-Agent\data -NoLogin
```

`-Distribution` selects or installs the named WSL distribution; `-DockerMode Existing` uses Docker Desktop already installed, while `-DockerMode Install` installs it. `-DataFolder` is a Linux application-data path. `-DatabaseFolder` is an optional Windows folder for only the database VHDX, and `-DockerFolder` chooses a Windows folder for Docker Desktop's disk image. `-StartAtSignIn` enables automatic startup. `-ListenAddress 0.0.0.0` exposes port 5050 to the host network and creates a scoped Windows Firewall rule. The default `127.0.0.1` listens only on this computer. The options are saved for future launches and upgrades.

If the default Docker Desktop disk location cannot preserve the required free space, the installer can move the image disk to the chosen database drive or another suitable fixed NTFS drive. It reads Docker Desktop's `CustomWslDistroDir` setting when checking that location. Changing Docker Desktop integration or moving its disk requires Docker Desktop to stop; the installer refuses to do that while other containers are running.

### Access from another device

For an HTTPS tunnel or a LAN address, pass one or more comma-separated origins, for example `-PublicUrl "https://ctf.example.com,http://192.0.2.10:5050"`. This binds to `0.0.0.0` unless you explicitly choose another listen address. The first HTTPS URL becomes the preferred public address. Local access at `http://127.0.0.1:5050` remains available. Browser POST requests from other origins are rejected, and the existing CSRF protection still applies. The application does not trust unverified proxy headers or forwarded client-IP headers.

With the default password-login mode, first administrator setup requires the one-time setup token shown during installation. With `-NoLogin` and network access enabled, every browser can open the service directly. `-OpenAccess:$false` opts into single-use connection links from `RemoteLink.cmd <public address>` for that installation or upgrade. Without network access, the local-only no-login default continues to connect each browser through `Start.cmd`. Open no-login access gives every visitor full administrator access, so limit reachability to networks you intend to trust. An HTTP LAN connection is unencrypted; use a TLS proxy or VPN for access over untrusted networks.

If the installer opens a Linux window while creating a new Ubuntu distribution, finish the Linux username and password prompts, then type `exit` at the Linux shell prompt. The Windows installer continues when that first-run window closes. It prepares a regular Linux user and enables Docker Desktop's WSL integration; changing integration may require Docker Desktop to restart. If other containers are running, the installer stops before changing Docker Desktop settings.

If an existing WSL distribution already runs its own Docker Engine, select or install a separate Ubuntu for CTF Agent. In interactive mode, choose the new-Ubuntu option; in unattended mode, pass `-Distribution Ubuntu-24.04` if that name is not already registered. The installer checks that its Linux Docker client and Windows Docker Desktop connect to the same engine. It leaves the existing engine and its containers running.

If a WSL distribution fails its readiness check, the installer prints the reason and tries another candidate. To retry a specific distribution, use `-Distribution <name>` under the **same Windows account** that owns it; if the check needs administrator privileges, rerun as that account with elevation. WSL registrations are per-user, so approving UAC through another Windows account will not access the original distribution.

### Put only the database in a Windows folder

Pass `-DatabaseFolder D:\CTF-Agent\data`, or enter that Windows folder at the database prompt with `-Interactive`. The installer creates or reuses `D:\CTF-Agent\data\ctf-agent-db.vhdx` for the database. C:, D:, E:, or any other fixed local drive can hold it, including the drive that holds the selected WSL distribution. D: is only an example; omitting the option keeps the database in WSL along with the other data. The application, challenge files, and other data remain at the selected WSL path. The installer creates a dynamically expanding ext4 VHDX with a 64 GB virtual limit and requires at least 5 GiB free on its Windows drive. Your signed-in Windows account must have administrator rights to attach the disk; approving UAC with a different account is not supported. It formats only a newly created, uniquely verified blank VHDX. An existing VHDX can be reused only when it contains the matching CTF Agent volume marker; it is never reformatted.

The database is visible in Explorer at `\\wsl.localhost\<distribution>\mnt\wsl\ctf-agent-db\Database\CTF_Agent`. The selected Windows folder contains the VHDX file rather than individual SQLite files. The launcher waits for Docker Desktop to become ready, then mounts and verifies the VHDX before starting CTF Agent containers. It exposes the database through a verified WSL-home link because Docker Desktop may not see a direct /mnt/wsl bind after a reboot. A fresh-container check confirms both paths refer to the live database. In this mode, container restart is disabled so it cannot start before the database mount. A new VHDX is created under the signed-in Windows account so that account can attach it again after a reboot without an elevated startup task.

This is a fresh-install choice. The installer does not move an existing database from its current location to the new VHDX. Uninstall.cmd removes any legacy managed mount task and detaches the VHDX after stopping the application, while keeping the VHDX file and the challenge data. If installation is interrupted after the new filesystem is verified, rerunning Install.cmd resumes using its recorded filesystem identity.

Open <http://127.0.0.1:5050> after installation. In password-login mode, create the first administrator account there; that setup page appears only before an administrator exists. Public password-login installs also require the setup token issued at installation. The explicitly selected no-login mode skips account setup.

To upgrade, use **Administration → Service updates** in the web interface. It checks the public GitHub release, shows its notes, downloads the installer ZIP, verifies its SHA-256 checksum, and updates the local Docker stack. If the new container does not become healthy, the update worker attempts to restore the previous installed release. You can also extract a newer release and run its `Install.cmd`. Data and the database each stay in their configured location; application releases are stored separately. The release installer resolves the public GHCR image tagged with the ZIP's commit SHA, pulls its immutable digest, and verifies the image revision and solver worker bytes. It uses that image directly without building a duplicate local runtime layer or the CTF toolchain. The separate small update controller is built locally. Docker may retain a shared public image cache after uninstall.
When a release changes the Windows launchers, run that release's `Install.cmd` once after a web update to refresh the copies under your Windows user profile. The Linux web updater does not replace those Windows files when WSL interop is unavailable. Existing installations with a separate database VHDX must run the patched release's Install.cmd once to migrate the database bind and host-side update worker before using web updates; do not use an older Start.cmd after a missing-data incident.

If Docker is unavailable inside the selected distribution, the installer checks the local Docker Desktop engine and the shared WSL CLI separately. It may restart Docker Desktop once to restore a missing shared CLI mount, only after confirming that no containers are running. Otherwise it reports the diagnosis without restarting Docker. If WSL integration is disabled, enable the distribution in **Docker Desktop → Settings → Resources → WSL Integration** and choose **Apply & Restart**. The installer reports completion only after `/readyz` returns HTTP 200; a failed readiness check keeps the installation settings and database for a retry.

An [upstream WSL issue](https://github.com/microsoft/WSL/issues/41084) describes shared `/mnt/wsl` mounts disappearing after another systemd distribution stops. A [fix was merged upstream](https://github.com/microsoft/WSL/pull/41086); check the installed WSL version when the Docker Desktop integration switch is already enabled but its CLI mount is missing. This behavior is a possible explanation, not a diagnosis of every missing Docker command.

## Challenge files in Windows Explorer

Keep the data directory in WSL's Linux filesystem. Open it in Explorer with `explorer.exe` from WSL or use a path like:

```text
\\wsl.localhost\<distribution>\home\<user>\.local\share\ctf-agent\ctf_agent_data\workspace_files
```

By default, the database and logs are stored separately under `Database/CTF_Agent` in the same WSL distribution. Docker's [WSL guidance](https://docs.docker.com/desktop/features/wsl/best-practices/) explains why Linux filesystem bind mounts perform better than files under `/mnt/c`. The optional Windows folder path is used for an ext4 VHDX; it does not bind mount SQLite files from NTFS.

## Install from source

From a WSL 2 distribution with Docker Desktop integration enabled:

```sh
git clone https://github.com/udonsari0101/CTF_Agent.git ~/CTF_Agent && cd ~/CTF_Agent && CTF_AUTH_MODE=password CTF_ALLOW_WEB_BOOTSTRAP=true CTF_LOCAL_UID=$(id -u) CTF_LOCAL_GID=$(id -g) python3 deploy/local-compose.py up -d --build
```

For a single-user installation without login, set `CTF_AUTH_MODE=nologin` and omit `CTF_ALLOW_WEB_BOOTSTRAP`. This mode should be selected explicitly.

To stop the source installation, run `python3 deploy/local-compose.py down` in the checkout. To update it, run `git pull --ff-only` and repeat the startup command. The web update worker is installed by the release installer; source checkouts use the source update command. The release installer uses a separate data path from a source checkout unless you select the same path.

The solver count starts from local CPU and memory recommendations, then grows with queued work. The web administration page can set a maximum. Resource warnings appear when demand exceeds the recommendation.
