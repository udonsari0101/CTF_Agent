$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $env:LOCALAPPDATA 'CTF Agent'
$stateFile = Join-Path $stateDir 'install.json'
if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) {
    throw 'CTF Agent installation settings are missing.'
}
$saved = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
$distro = [string]$saved.distro
$linuxHome = [string]$saved.home
if (-not $distro -or $linuxHome -notmatch '^/[^\x00-\x1f]*$' -or
    $linuxHome -match '(^|/)\.\.(/|$)' -or $linuxHome -eq '/') {
    throw 'CTF Agent installation settings are invalid.'
}
$linuxPath = "$linuxHome/.launcher/uninstall.py"
& wsl.exe --distribution $distro --exec test -f $linuxPath *> $null
if ($LASTEXITCODE -ne 0) {
    $uninstaller = Join-Path $PSScriptRoot 'installer\uninstall.py'
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'CTF Agent removal script is missing.' }
    $converted = @(& wsl.exe --distribution $distro --exec wslpath -a -u $uninstaller 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $converted.Count) { throw 'The removal script is unavailable in WSL.' }
    $linuxPath = $converted[0]
}
Write-Host "CTF Agent containers, images and release files will be removed from $distro."
Write-Host "These folders will stay: $linuxHome/ctf_agent_data and $linuxHome/Database/CTF_Agent"
Write-Host 'The WSL distribution and Docker Desktop will stay installed.'
$answer = (Read-Host 'Continue? [y/N]').Trim().ToLowerInvariant()
if ($answer -notin @('y', 'yes')) { Write-Host 'Removal cancelled.'; exit 0 }
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
if (-not $ready) { throw "Docker Desktop is unavailable inside $distro. Nothing was deleted." }
& wsl.exe --distribution $distro --exec env "CTF_LOCAL_HOME=$linuxHome" python3 $linuxPath
if ($LASTEXITCODE -ne 0) { throw "CTF Agent removal failed (exit code $LASTEXITCODE). Data was preserved." }
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'CTF Agent Local.lnk'
if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
    if ($shortcut.TargetPath -eq (Join-Path $stateDir 'Start.cmd')) {
        Remove-Item -LiteralPath $shortcutPath
    }
}
Write-Host 'CTF Agent was removed. The selected data and database folders are still available.'
