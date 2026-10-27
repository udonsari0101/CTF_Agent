$ErrorActionPreference = 'Stop'
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

function Test-WslDockerReady([string]$distro) {
    $result = Invoke-WslNative @('--distribution', $distro, '--exec', 'docker', 'info') -Quiet
    return ($result.ExitCode -eq 0)
}
$stateFile = Join-Path $env:LOCALAPPDATA 'CTF Agent\install.json'
if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
    throw 'CTF Agent installation settings are missing. Run Install.cmd first.'
}
$saved = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ($saved.pending_install) { throw 'Installation is incomplete. Rerun Install.cmd to resume it.' }
$distro = [string]$saved.distro
$linuxHome = [string]$saved.home
if (-not $distro -or $linuxHome -notmatch '^/[^\x00-\x1f]*$' -or
    $linuxHome -match '(^|/)\.\.(/|$)' -or $linuxHome -eq '/') {
    throw 'CTF Agent installation settings are invalid.'
}
$databasePath = ''
$databaseMount = ''
$dbVhd = [string]$saved.db_vhd
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
    Assert-DatabaseVhdPath $dbVhd | Out-Null
    Ensure-DatabaseMount $distro $dbVhd $dbUuid ([bool]$saved.db_task_managed)
}
$linuxPath = "$linuxHome/.launcher/start.sh"
$exists = Invoke-WslNative @('--distribution', $distro, '--exec', 'test', '-f', $linuxPath) -Quiet
if ($exists.ExitCode -ne 0) {
    $launcher = Join-Path $PSScriptRoot 'installer\start.sh'
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw 'CTF Agent start script is missing.' }
    $pathResult = Invoke-WslNative @('--distribution', $distro, '--exec', 'wslpath', '-a', '-u', $launcher)
    $converted = @($pathResult.Output)
    if ($pathResult.ExitCode -ne 0 -or -not $converted.Count) { throw 'The start script is unavailable in WSL.' }
    $linuxPath = $converted[0]
}
$desktop = @(
    (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe')
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue) -and $desktop) {
    Start-Process -FilePath $desktop -WindowStyle Hidden
}
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if (Test-WslDockerReady $distro) { $ready = $true; break }
    Start-Sleep -Seconds 4
}
if (-not $ready) { throw "Docker Desktop is unavailable inside $distro." }
$launch = Invoke-WslNative @('--distribution', $distro, '--exec', 'env',
    "CTF_LOCAL_HOME=$linuxHome", "CTF_LOCAL_DATABASE=$databasePath",
    "CTF_LOCAL_FS_DATABASE=$databasePath", "CTF_LOCAL_DB_MOUNT=$databaseMount",
    'bash', $linuxPath) -Visible
if ($launch.ExitCode -ne 0) { throw "CTF Agent start failed (exit code $($launch.ExitCode))." }
