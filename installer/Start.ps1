$ErrorActionPreference = 'Stop'
$stateFile = Join-Path $env:LOCALAPPDATA 'CTF Agent\install.json'
if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
    throw 'CTF Agent installation settings are missing. Run Install.cmd first.'
}
$saved = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
$distro = [string]$saved.distro
$linuxHome = [string]$saved.home
if (-not $distro -or $linuxHome -notmatch '^/[^\x00-\x1f]*$' -or
    $linuxHome -match '(^|/)\.\.(/|$)' -or $linuxHome -eq '/') {
    throw 'CTF Agent installation settings are invalid.'
}
$linuxPath = "$linuxHome/.launcher/start.sh"
& wsl.exe --distribution $distro --exec test -f $linuxPath *> $null
if ($LASTEXITCODE -ne 0) {
    $launcher = Join-Path $PSScriptRoot 'installer\start.sh'
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw 'CTF Agent start script is missing.' }
    $converted = @(& wsl.exe --distribution $distro --exec wslpath -a -u $launcher 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $converted.Count) { throw 'The start script is unavailable in WSL.' }
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
    & wsl.exe --distribution $distro --exec docker info *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 4
}
if (-not $ready) { throw "Docker Desktop is unavailable inside $distro." }
& wsl.exe --distribution $distro --exec env "CTF_LOCAL_HOME=$linuxHome" bash $linuxPath
if ($LASTEXITCODE -ne 0) { throw "CTF Agent start failed (exit code $LASTEXITCODE)." }
