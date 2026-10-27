$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'installer\install.sh'
$stateFile = Join-Path $env:LOCALAPPDATA 'CTF Agent\install.json'
$minimumFreeBytes = 15GB
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Release archive is incomplete.' }

function Ask-YesNo([string]$question, [bool]$default = $true) {
    $hint = if ($default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $answer = (Read-Host "$question [$hint]").Trim().ToLowerInvariant()
        if (-not $answer) { return $default }
        if ($answer -in @('y', 'yes')) { return $true }
        if ($answer -in @('n', 'no')) { return $false }
        Write-Host 'Enter Y or N.'
    }
}

function Get-WslNames {
    $lines = @(& wsl.exe --list --quiet 2>$null)
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($lines | ForEach-Object { ($_ -replace "`0", '').Trim() } |
        Where-Object { $_ -and $_ -notlike 'docker-desktop*' } | Select-Object -Unique)
}

function Get-WslVersions {
    $versions = @{}
    $lines = @(& wsl.exe --list --verbose 2>$null)
    if ($LASTEXITCODE -ne 0) { return $versions }
    foreach ($line in $lines) {
        $clean = ($line -replace "`0", '').Trim().TrimStart('*').Trim()
        if ($clean -match '^(.+?)\s+.+\s+([12])\s*$') { $versions[$Matches[1].Trim()] = [int]$Matches[2] }
    }
    return $versions
}

function Invoke-WslPython([string]$name, [string]$source, [string[]]$arguments = @()) {
    # Windows PowerShell 5.1 changes quotes inside a multiline native argument.
    # Pass a single-line wrapper without quoted literals; Python decodes the
    # original source from a separate argument before forwarding its argv.
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
    $program = 'import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))'
    $previousPreference = $ErrorActionPreference
    try {
        # A probe failure is reported through its exit code, not a native stderr
        # ErrorRecord that terminates the installer before it can offer recovery.
        $ErrorActionPreference = 'Continue'
        $output = @(& wsl.exe --distribution $name --exec python3 -c $program $encoded @arguments 2>$null)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{ Output = ($output -join "`n"); ExitCode = $exitCode }
}

function Get-WslInfo([string]$name, [hashtable]$versions) {
    $probe = @'
import json,os,shutil,sys
data={}
try:
    for line in open('/etc/os-release',encoding='utf-8'):
        if '=' in line:
            key,value=line.rstrip('\n').split('=',1)
            data[key]=value.strip('"')
except OSError:
    pass
print(json.dumps({'id':data.get('ID',''),'version':data.get('VERSION_ID',''),
                  'home':os.path.expanduser('~'),'python':list(sys.version_info[:2]),
                  'bash':bool(shutil.which('bash'))}))
'@
    $probeResult = Invoke-WslPython $name $probe
    $result = $null
    if ($probeResult.ExitCode -eq 0) {
        try { $result = ($probeResult.Output | ConvertFrom-Json) } catch { $result = $null }
    }
    $version = if ($versions.ContainsKey($name)) { [int]$versions[$name] } else { 0 }
    $score = 0
    if ($version -eq 2 -and $result -and $result.bash -and
        ($result.python[0] -gt 3 -or ($result.python[0] -eq 3 -and $result.python[1] -ge 10))) {
        $score = 60
        if ($result.id -eq 'ubuntu') {
            $ubuntuVersion = $null
            if (-not [version]::TryParse([string]$result.version, [ref]$ubuntuVersion)) { $ubuntuVersion = [version]'0.0' }
            $score = if ($ubuntuVersion -ge [version]'24.04') { 100 } else { 90 }
        }
        elseif ($result.id -eq 'debian') { $score = 80 }
    }
    $reason = if ($version -ne 2) { 'WSL 2 required' }
        elseif (-not $result) { 'Python 3 unavailable or distribution not initialized' }
        elseif (-not $result.bash) { 'bash unavailable' }
        elseif ($score -eq 0) { 'Python 3.10+ required' }
        else { 'recommended' }
    return [pscustomobject]@{Name=$name;Version=$version;Score=$score;Reason=$reason;
        Home=if ($result) { [string]$result.home } else { '' };
        Linux=if ($result) { "$($result.id) $($result.version)".Trim() } else { '' }}
}

function Get-OnlineUbuntu {
    $lines = @(& wsl.exe --list --online 2>$null) | ForEach-Object { $_ -replace "`0", '' }
    if (($lines -join "`n") -match '(?m)^\s*Ubuntu-24\.04\s') { return 'Ubuntu-24.04' }
    return 'Ubuntu'
}

function Install-WslDistribution([string]$name) {
    Write-Host "Installing WSL distribution: $name"
    $process = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\wsl.exe') `
        -ArgumentList @('--install', '--distribution', $name) -Verb RunAs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "WSL installation exited with code $($process.ExitCode). Restart Windows if prompted, then rerun Install.cmd."
    }
    Write-Host 'Complete the Linux first-run username setup if prompted.'
    if ($name -notin @(Get-WslNames)) {
        Write-Host 'Restart Windows, finish WSL setup, and rerun Install.cmd.'
        exit 20
    }
}

function Select-WslDistribution([object[]]$infos, [string]$savedName) {
    $ready = @($infos | Where-Object { $_.Score -gt 0 } | Sort-Object Score -Descending)
    if (-not $ready.Count) {
        $candidate = Get-OnlineUbuntu
        if (-not (Ask-YesNo "No suitable WSL 2 distribution was found. Install $candidate now?")) {
            throw 'A WSL 2 distribution with bash and Python 3.10+ is required.'
        }
        Install-WslDistribution $candidate
        return $candidate
    }
    Write-Host 'Available WSL distributions:'
    $ordered = @($infos | Sort-Object Score -Descending)
    for ($index = 0; $index -lt $ordered.Count; $index++) {
        $info = $ordered[$index]
        $label = if ($info.Score -gt 0) { 'usable' } else { $info.Reason }
        Write-Host "  $($index + 1). $($info.Name) ($($info.Linux), WSL $($info.Version)) - $label"
    }
    $default = 1
    if ($savedName) {
        for ($index = 0; $index -lt $ordered.Count; $index++) {
            if ($ordered[$index].Name -eq $savedName -and $ordered[$index].Score -gt 0) {
                $default = $index + 1
                break
            }
        }
    }
    while ($true) {
        $answer = (Read-Host "Choose distribution [$default], or N for a new Ubuntu").Trim()
        if (-not $answer) { $answer = [string]$default }
        if ($answer -in @('n', 'N')) {
            $candidate = Get-OnlineUbuntu
            if (Ask-YesNo "Install $candidate now?") { Install-WslDistribution $candidate; return $candidate }
            continue
        }
        $number = 0
        if ([int]::TryParse($answer, [ref]$number) -and $number -ge 1 -and $number -le $ordered.Count) {
            $selected = $ordered[$number - 1]
            if ($selected.Score -gt 0) { return $selected.Name }
            Write-Host "This distribution is not suitable: $($selected.Reason)"
        } else { Write-Host 'Choose one of the displayed numbers.' }
    }
}

function Get-HostVolumeFree([string]$path) {
    $expanded = [Environment]::ExpandEnvironmentVariables($path)
    if ($expanded -match '^[A-Za-z]:$') { $expanded += '\' }
    $root = [IO.Path]::GetPathRoot($expanded)
    if (-not $root -or $root.StartsWith('\\')) { throw "Cannot check the Windows volume for $path" }
    return [int64](Get-PSDrive -Name $root.Substring(0, 1) -ErrorAction Stop).Free
}

function Assert-StorageCapacity([string]$distro, [string]$linuxHome) {
    $diskProbe = @'
import json,os,shutil,sys
p=sys.argv[1]
while not os.path.exists(p):
    parent=os.path.dirname(p)
    if parent==p: raise SystemExit(2)
    p=parent
print(json.dumps({'free':shutil.disk_usage(p).free,'existing':p}))
'@
    $probeResult = Invoke-WslPython $distro $diskProbe @($linuxHome)
    if ($probeResult.ExitCode -ne 0) { throw 'Could not check free space inside the selected WSL distribution.' }
    $wslFree = [int64](($probeResult.Output | ConvertFrom-Json).free)
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    $registered = @(Get-ChildItem -Path $key -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty -Path $_.PSPath } |
        Where-Object { $_.DistributionName -eq $distro } | Select-Object -First 1)
    if (-not $registered.Count -or -not $registered[0].BasePath) {
        throw 'Could not locate the selected WSL disk on Windows.'
    }
    $hostFree = Get-HostVolumeFree ([string]$registered[0].BasePath)
    Write-Host ('WSL free: {0:N1} GB; Windows backing volume free: {1:N1} GB' -f ($wslFree / 1GB), ($hostFree / 1GB))
    if ($wslFree -lt $minimumFreeBytes -or $hostFree -lt $minimumFreeBytes) {
        throw 'At least 15 GB free space is required both inside WSL and on its Windows backing volume.'
    }
    if ((Get-HostVolumeFree $env:SystemDrive) -lt $minimumFreeBytes) {
        Write-Warning 'The Windows system drive has less than 15 GB free. Docker Desktop may need more space there.'
    }
}

function Get-DockerDesktopExecutable {
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Ensure-DockerDesktop([string]$distro) {
    $desktop = Get-DockerDesktopExecutable
    if (-not $desktop) {
        if (-not (Ask-YesNo 'Docker Desktop is not installed. Install it with winget now?')) {
            throw 'Docker Desktop is required.'
        }
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            Start-Process 'https://docs.docker.com/desktop/setup/install/windows-install/'
            throw 'winget is unavailable. Install Docker Desktop from the opened official page and rerun Install.cmd.'
        }
        & winget.exe install --id Docker.DockerDesktop --exact --source winget `
            --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) { throw "Docker Desktop installation failed (exit code $LASTEXITCODE)." }
        $desktop = Get-DockerDesktopExecutable
        if (-not $desktop) { throw 'Finish Docker Desktop installation and rerun Install.cmd.' }
    }
    if (-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath $desktop
    }
    for ($round = 1; $round -le 3; $round++) {
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            & wsl.exe --distribution $distro --exec docker info *> $null
            if ($LASTEXITCODE -eq 0) { return }
            Start-Sleep -Seconds 5
        }
        if ($round -lt 3) {
            Write-Host "Docker is unavailable inside $distro. Enable Settings > Resources > WSL Integration in Docker Desktop."
            Read-Host 'Finish Docker Desktop setup and press Enter to retry' | Out-Null
        }
    }
    throw "Docker Desktop WSL integration is unavailable in $distro. Enable it and rerun Install.cmd."
}

Write-Host 'CTF Agent local installer'
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'This Windows version does not provide wsl.exe. Update Windows and rerun Install.cmd.'
}
$saved = $null
if (Test-Path -LiteralPath $stateFile -PathType Leaf) {
    try { $saved = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $saved = $null }
}
$names = @(Get-WslNames)
$infos = @($names | ForEach-Object { Get-WslInfo $_ (Get-WslVersions) })
$distro = Select-WslDistribution $infos ([string]$saved.distro)
$selectedInfo = Get-WslInfo $distro (Get-WslVersions)
if ($selectedInfo.Score -le 0) {
    Write-Host 'Finish WSL setup or restart Windows, then rerun Install.cmd.'
    exit 20
}
$defaultHome = "$($selectedInfo.Home.TrimEnd('/'))/.local/share/ctf-agent"
if ($saved -and $saved.distro -eq $distro -and $saved.home) { $defaultHome = [string]$saved.home }
Write-Host "Recommended data folder: $defaultHome"
Write-Host "Windows Explorer: \\wsl.localhost\$distro\$($defaultHome.TrimStart('/') -replace '/', '\')"
while ($true) {
    $answer = (Read-Host 'Data folder inside WSL [Enter for the recommendation]').Trim()
    $linuxHome = if ($answer) { $answer } else { $defaultHome }
    if ($linuxHome -match '^[A-Za-z]:[\\/]' -or $linuxHome.StartsWith('\\')) {
        Write-Host 'Choose a WSL Linux path. Explorer can open it through \\wsl.localhost without a slow Windows bind mount.'
        continue
    }
    if (-not $linuxHome.StartsWith('/') -or $linuxHome -match '[\x00-\x1f]' -or
        $linuxHome -match '(^|/)\.\.(/|$)' -or $linuxHome -match '^/mnt/[A-Za-z](/|$)') {
        Write-Host 'Enter an absolute WSL Linux path outside /mnt/<Windows drive>.'
        continue
    }
    break
}
if ($saved -and ($saved.distro -ne $distro -or $saved.home -ne $linuxHome) -and
    -not (Ask-YesNo 'This changes the data location. Existing data will not move automatically. Continue?' $false)) {
    throw 'Installation cancelled; existing data was not changed.'
}
Assert-StorageCapacity $distro $linuxHome
$autoStartDefault = if ($saved -and $null -ne $saved.autoStart) { [bool]$saved.autoStart } else { $true }
$autoStart = Ask-YesNo 'Start CTF Agent automatically when you sign in to Windows?' $autoStartDefault
$loginDefault = -not ($saved -and $saved.authMode -eq 'nologin')
$requireLogin = Ask-YesNo 'Require account login on this computer?' $loginDefault
$authMode = if ($requireLogin) { 'password' } else { 'nologin' }
Ensure-DockerDesktop $distro
$linuxPath = @(& wsl.exe --distribution $distro --exec wslpath -a -u $installer 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $linuxPath.Count -or -not $linuxPath[0].StartsWith('/')) {
    throw 'The selected WSL distribution cannot access the extracted release folder.'
}
& wsl.exe --distribution $distro --exec env "CTF_LOCAL_HOME=$linuxHome" "CTF_LOCAL_AUTOSTART=$($autoStart.ToString().ToLowerInvariant())" "CTF_LOCAL_AUTH_MODE=$authMode" bash $linuxPath[0]
if ($LASTEXITCODE -ne 0) { throw "Local installation failed (exit code $LASTEXITCODE)." }
$stateDir = Split-Path -Parent $stateFile
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
foreach ($name in @('Start.cmd', 'Start.ps1', 'Uninstall.cmd', 'Uninstall.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stateDir $name) -Force
}
@{distro=$distro;home=$linuxHome;autoStart=$autoStart;authMode=$authMode} | ConvertTo-Json |
    Set-Content -LiteralPath $stateFile -Encoding UTF8
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'CTF Agent Local.lnk'
$targetPath = Join-Path $stateDir 'Start.cmd'
$shell = New-Object -ComObject WScript.Shell
if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
    $existing = $shell.CreateShortcut($shortcutPath)
    if ($existing.TargetPath -ne $targetPath) { throw 'A different startup shortcut uses the CTF Agent name.' }
    if (-not $autoStart) { Remove-Item -LiteralPath $shortcutPath }
}
if ($autoStart) {
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $targetPath
    $shortcut.WorkingDirectory = $stateDir
    $shortcut.WindowStyle = 7
    $shortcut.Save()
}
Write-Host "Start: $(Join-Path $stateDir 'Start.cmd')"
Write-Host "Uninstall: $(Join-Path $stateDir 'Uninstall.cmd')"
if ($requireLogin) { Write-Host 'Open http://127.0.0.1:5050 to create the first administrator account.' }
else { Write-Host 'Open http://127.0.0.1:5050.' }
Write-Host "Files in Explorer: \\wsl.localhost\$distro\$($linuxHome.TrimStart('/') -replace '/', '\')\ctf_agent_data\workspace_files"
