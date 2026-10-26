# Windows installation with Docker Desktop

## Release installer

Download and extract the latest [Windows release ZIP](https://github.com/udonsari0101/CTF_Agent/releases/latest), then run `Install.cmd`.

The installer checks WSL 2, recommends an installed Linux distribution or offers to install Ubuntu, checks Docker Desktop and its WSL integration, and verifies at least 15 GB of free space in WSL and on the backing Windows volume. Choose an absolute path inside the WSL Linux filesystem for your data. The suggested path is `~/.local/share/ctf-agent` in the selected distribution. The installer stores your choice for upgrades.

Open <http://127.0.0.1:5050> after installation. Create the first administrator account there. That setup page is available only before an administrator exists. Later visits use the login page.

To upgrade, use **Administration → Service updates** in the web interface. Release v0.3.0 has no web update worker, so run the newer release's `Install.cmd` once to enable this feature. It checks the public GitHub release, shows its notes, downloads the installer ZIP, verifies its SHA-256 checksum, and updates the local Docker stack. If the new container does not become healthy, the update worker attempts to restore the previous installed release. You can also extract a newer release and run its `Install.cmd`. Data and the database stay in the selected directory; application releases are stored separately. The first install builds a large toolchain image. Later updates reuse it when the toolchain files have not changed.

If the installer asks you to enable WSL integration, open **Docker Desktop → Settings → Resources → WSL Integration**, enable the selected distribution, and retry. Follow any Windows restart prompt before rerunning the installer.

## Challenge files in Windows Explorer

Keep the data directory in WSL's Linux filesystem. Open it in Explorer with `explorer.exe` from WSL or use a path like:

```text
\\wsl.localhost\<distribution>\home\<user>\.local\share\ctf-agent\ctf_agent_data\workspace_files
```

The database and logs are stored separately under `Database/CTF_Agent`. Docker's [WSL guidance](https://docs.docker.com/desktop/features/wsl/best-practices/) explains why Linux filesystem bind mounts perform better than files under `/mnt/c`.

## Install from source

From a WSL 2 distribution with Docker Desktop integration enabled:

```sh
git clone https://github.com/udonsari0101/CTF_Agent.git ~/CTF_Agent && cd ~/CTF_Agent && CTF_AUTH_MODE=password CTF_ALLOW_WEB_BOOTSTRAP=true CTF_LOCAL_UID=$(id -u) CTF_LOCAL_GID=$(id -g) python3 deploy/local-compose.py up -d --build
```

For a single-user installation without login, set `CTF_AUTH_MODE=nologin` and omit `CTF_ALLOW_WEB_BOOTSTRAP`. This mode should be selected explicitly.

To stop the source installation, run `python3 deploy/local-compose.py down` in the checkout. To update it, run `git pull --ff-only` and repeat the startup command. The web update worker is installed by the release installer; source checkouts use the source update command. The release installer uses a separate data path from a source checkout unless you select the same path.

The solver count starts from local CPU and memory recommendations, then grows with queued work. The web administration page can set a maximum. Resource warnings appear when demand exceeds the recommendation.

## 한국어 요약

릴리스 ZIP을 풀고 `Install.cmd`를 실행하세요. 설치기는 적합한 WSL 배포판을 추천하고 Docker Desktop 연결·디스크 여유 공간을 확인한 뒤 데이터 경로를 묻습니다. 데이터는 Windows 드라이브의 `/mnt/c` 대신 WSL 내부 Linux 경로에 두고, Windows 파일 탐색기에서는 `\\wsl.localhost`로 열면 됩니다. 설치 후 <http://127.0.0.1:5050>에서 최초 관리자 계정을 만드세요. 새 버전 ZIP의 `Install.cmd`를 다시 실행하면 기존 데이터와 DB를 유지하며 업데이트합니다.
