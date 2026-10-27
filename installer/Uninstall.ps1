$ErrorActionPreference = 'Stop'
$dockerDesktopHelper = Join-Path $PSScriptRoot 'DockerDesktop.ps1'
if (-not (Test-Path -LiteralPath $dockerDesktopHelper -PathType Leaf)) { throw 'DockerDesktop.ps1 is missing. Reinstall the patched release.' }
. $dockerDesktopHelper
function Invoke-WslNative([string[]]$command, [switch]$Quiet, [switch]$Visible) {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($Quiet) { & wsl.exe @command *> $null; $output = @() }
        elseif ($Visible) { & wsl.exe @command | Out-Host; $output = @() }
        else { $output = @(& wsl.exe @command 2>$null) }
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    return [pscustomobject]@{ Output=$output; ExitCode=$exitCode }
}

$stateDir = Join-Path $env:LOCALAPPDATA 'CTF Agent'
$stateFile = Join-Path $stateDir 'install.json'
if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
    throw 'CTF Agent installation settings are missing.'
}
$saved = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ($saved.pending_install) { throw 'Installation is incomplete. Rerun Install.cmd before uninstalling.' }
$distro = [string]$saved.distro
$linuxHome = [string]$saved.home
if (-not $distro -or $linuxHome -notmatch '^/[^\x00-\x1f]*$' -or
    $linuxHome -match '(^|/)\.\.(/|$)' -or $linuxHome -eq '/') {
    throw 'CTF Agent installation settings are invalid.'
}
$dbVhd = [string]$saved.db_vhd
$databasePath = ''
$databaseMount = ''
if ($dbVhd) {
    $helper = Join-Path $PSScriptRoot 'DatabaseDisk.ps1'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
        throw 'The database disk helper is missing. Reinstall the same release.'
    }
    . $helper
    $databaseMount = [string]$saved.database_mount
    $databasePath = [string]$saved.database_path
    $dbUuid = [string]$saved.db_uuid
    if ($databaseMount -ne (Get-DatabaseMountPath) -or
        $databasePath -ne "$databaseMount/Database/CTF_Agent" -or
        $dbUuid -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
        throw 'The separate database settings are invalid.'
    }
}
$linuxPath = "$linuxHome/.launcher/uninstall.py"
$exists = Invoke-WslNative @('--distribution', $distro, '--exec', 'test', '-f', $linuxPath) -Quiet
if ($exists.ExitCode -ne 0) {
    $uninstaller = Join-Path $PSScriptRoot 'installer\uninstall.py'
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'CTF Agent removal script is missing.' }
    $pathResult = Invoke-WslNative @('--distribution', $distro, '--exec', 'wslpath', '-a', '-u', $uninstaller)
    $converted = @($pathResult.Output)
    if ($pathResult.ExitCode -ne 0 -or -not $converted.Count) { throw 'The removal script is unavailable in WSL.' }
    $linuxPath = $converted[0]
}
Write-Host "CTF Agent containers, images and release files will be removed from $distro."
if ($dbVhd) {
    Write-Host "These locations will stay: $linuxHome/ctf_agent_data and $dbVhd"
} else {
    Write-Host "These folders will stay: $linuxHome/ctf_agent_data and $linuxHome/Database/CTF_Agent"
}
Write-Host 'The WSL distribution and Docker Desktop will stay installed.'
$answer = (Read-Host 'Continue? [y/N]').Trim().ToLowerInvariant()
if ($answer -notin @('y', 'yes')) { Write-Host 'Removal cancelled.'; exit 0 }
if ($dbVhd) {
    Ensure-DatabaseMount $distro $dbVhd $dbUuid ([bool]$saved.db_task_managed)
}
$desktop = @(
    (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe')
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue) -and $desktop) {
    Start-Process -FilePath $desktop -WindowStyle Hidden
}
Wait-WslDockerReady $distro -AllowRepair
$removal = Invoke-WslNative @('--distribution', $distro, '--exec', 'env',
    "CTF_LOCAL_HOME=$linuxHome", "CTF_LOCAL_DATABASE=$databasePath",
    "CTF_LOCAL_FS_DATABASE=$databasePath", "CTF_LOCAL_DB_MOUNT=$databaseMount",
    'python3', $linuxPath) -Visible
if ($removal.ExitCode -ne 0) { throw "CTF Agent removal failed (exit code $($removal.ExitCode)). Data was preserved." }
if ($dbVhd) {
    if ($saved.db_task_managed) {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Invoke-ElevatedDatabaseAction 'unregister-task' $dbVhd $sid
    }
    Invoke-ElevatedDatabaseAction 'unmount' $dbVhd
}
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'CTF Agent Local.lnk'
if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
    if ($shortcut.TargetPath -eq (Join-Path $stateDir 'Start.cmd')) {
        Remove-Item -LiteralPath $shortcutPath
    }
}
Write-Host 'CTF Agent was removed. The selected data and database folders are still available.'
