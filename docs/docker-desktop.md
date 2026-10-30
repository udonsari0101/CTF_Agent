# Windows installation with Docker Desktop

## Release installer

Download and extract the latest [Windows release ZIP](https://github.com/udonsari0101/CTF_Agent/releases/latest), then run `Install.cmd`.

During installation choose whether CTF Agent starts when you sign in to Windows and whether local users must log in. The installer creates Start.cmd and Uninstall.cmd in the CTF Agent folder under your local Windows app data directory. Click Start.cmd whenever you want to run the service manually. Uninstall.cmd confirms the two retained data paths, then removes only CTF Agent containers, its image tags, and its installed release files. It does not unregister WSL, uninstall Docker Desktop, remove other containers, or delete the selected data and database folders. If Docker is unavailable, removal stops before deleting release files so you can retry after Docker Desktop starts.

The installer checks WSL 2, recommends an installed Linux distribution or offers to install Ubuntu, checks Docker Desktop and its WSL integration, and verifies at least 15 GB of free space in WSL and on the backing Windows volume. At the data path prompt, press Enter for the usual Linux filesystem location (`~/.local/share/ctf-agent` in the selected distribution). The installer stores your choice for upgrades.

If the installer opens a Linux window while creating a new Ubuntu distribution, finish the Linux username and password prompts, then type `exit` at the Linux shell prompt. The Windows installer continues when that first-run window closes. In Docker Desktop, enable **Settings → Resources → WSL Integration** for the new distribution if asked.

If an existing WSL distribution already runs its own Docker Engine, choose **N** at the distribution prompt to create a separate Ubuntu for CTF Agent. The installer checks that its Linux Docker client and Windows Docker Desktop connect to the same engine. It leaves the existing engine and its containers running.

If installed WSL distributions appear but their readiness checks fail, review the reason shown for each distribution. Run `Install.cmd` again as administrator under the **same Windows account** that owns them. WSL registrations are per-user; installing another Ubuntu does not fix a failed readiness check for an existing distribution.

### Put only the database in a Windows folder

At the first data path prompt, paste a Windows folder path such as `D:\CTF-Agent\data` from Explorer. The installer creates or reuses `D:\CTF-Agent\data\ctf-agent-db.vhdx` for the database. C:, D:, E:, or any other fixed local drive can hold it, including the drive that holds the selected WSL distribution. D: is only an example; pressing Enter keeps the database in WSL along with the other data. The application, challenge files, and other data remain at the suggested WSL path. If you choose a custom WSL data path instead, the later optional database prompt can still accept a Windows location on a fixed local drive. The installer creates a dynamically expanding ext4 VHDX with a 64 GB virtual limit and requires at least 15 GB free on its Windows drive. Your signed-in Windows account must have administrator rights to attach the disk; approving UAC with a different account is not supported. It formats only a newly created, uniquely verified blank VHDX. An existing VHDX can be reused only when it contains the matching CTF Agent volume marker; it is never reformatted.

The database is visible in Explorer at `\\wsl.localhost\<distribution>\mnt\wsl\ctf-agent-db\Database\CTF_Agent`. The selected Windows folder contains the VHDX file rather than individual SQLite files. The launcher waits for Docker Desktop to become ready, then mounts and verifies the VHDX before starting CTF Agent containers. It exposes the database through a verified WSL-home link because Docker Desktop may not see a direct /mnt/wsl bind after a reboot. A fresh-container check confirms both paths refer to the live database. In this mode, container restart is disabled so it cannot start before the database mount. If Windows sign-in startup is enabled, the installer registers a narrowly scoped elevated task to mount the VHDX before the startup launcher runs. With startup disabled, launching Start.cmd after a reboot may show a Windows administrator prompt to attach the disk.

This is a fresh-install choice. The installer does not move an existing database from its current location to the new VHDX. Uninstall.cmd removes the managed mount task and detaches the VHDX after stopping the application, while keeping the VHDX file and the challenge data. If installation is interrupted after the new filesystem is verified, rerunning Install.cmd resumes using its recorded filesystem identity.

Open <http://127.0.0.1:5050> after installation. Create the first administrator account there. That setup page is available only before an administrator exists. Later visits use the login page.

To upgrade, use **Administration → Service updates** in the web interface. Release v0.3.0 has no web update worker, so run the newer release's `Install.cmd` once to enable this feature. It checks the public GitHub release, shows its notes, downloads the installer ZIP, verifies its SHA-256 checksum, and updates the local Docker stack. If the new container does not become healthy, the update worker attempts to restore the previous installed release. You can also extract a newer release and run its `Install.cmd`. Data and the database each stay in their configured location; application releases are stored separately. The release installer resolves the public GHCR image tagged with the ZIP's commit SHA, pulls its immutable digest, and verifies the image revision. It builds a small local policy layer from that verified base; it does not rebuild the CTF toolchain. The separate small update controller is built locally. Docker may retain a shared public image cache after uninstall.
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

## 한국어 요약

릴리스 ZIP을 풀고 `Install.cmd`를 실행하세요. 설치기는 적합한 WSL 배포판을 추천하고 Docker Desktop 연결·디스크 여유 공간을 확인한 뒤 데이터 경로를 묻습니다. Enter를 누르면 기존 WSL 경로를 사용합니다. `D:\CTF-Agent\data` 같은 Windows 폴더 경로를 붙여 넣으면 프로그램·문제 파일은 기존 WSL 경로에 두고 DB만 해당 폴더의 ext4 VHDX에 저장합니다. C:, D:, E: 등 로컬 고정 드라이브라면 WSL과 같은 드라이브도 가능합니다. D:는 예시일 뿐입니다. Windows 파일 탐색기에서는 WSL 내부 파일을 `\\wsl.localhost`로 열 수 있습니다. 설치 후 <http://127.0.0.1:5050>에서 최초 관리자 계정을 만드세요. 새 버전 ZIP의 `Install.cmd`를 다시 실행하면 기존 데이터와 DB를 유지하며 업데이트합니다.
