$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\installer\DockerDisk.ps1')

$root = Join-Path $env:RUNNER_TEMP ('ctf-agent-docker-disk-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $default = Join-Path $root 'default'
    $defaultDisk = Join-Path $default 'disk\docker_data.vhdx'
    New-Item -ItemType Directory -Path (Split-Path -Parent $defaultDisk) -Force | Out-Null
    New-Item -ItemType File -Path $defaultDisk | Out-Null
    $settings = Join-Path $root 'settings.json'
    '{}' | Set-Content -LiteralPath $settings -Encoding UTF8
    if ((Resolve-DockerDesktopDiskFile -SettingsFile $settings -DefaultFolder $default -OverrideFolder '') -ne $defaultDisk) {
        throw 'Default Docker Desktop image disk was not detected'
    }

    $custom = Join-Path $root 'custom'
    $customDisk = Join-Path $custom 'docker_data.vhdx'
    New-Item -ItemType Directory -Path $custom | Out-Null
    New-Item -ItemType File -Path $customDisk | Out-Null
    @{ dataFolder = $custom } | ConvertTo-Json | Set-Content -LiteralPath $settings -Encoding UTF8
    if ((Resolve-DockerDesktopDiskFile -SettingsFile $settings -DefaultFolder $default -OverrideFolder '') -ne $customDisk) {
        throw 'Configured Docker Desktop image disk was not detected'
    }
    if ((Resolve-DockerDesktopDiskFile -SettingsFile $settings -DefaultFolder $default -OverrideFolder $default) -ne $defaultDisk) {
        throw 'Explicit Docker Desktop image disk override was not honored'
    }

    function Get-HostVolumeFree([string]$Path) { return $script:mockFree }
    $script:mockFree = [int64]15GB
    Assert-DockerDesktopImageCapacity -EstimatedWriteBytes ([int64]10GB) `
        -SettingsFile $settings -DefaultFolder $default -OverrideFolder ''
    $script:mockFree = [int64]15GB - 1
    try {
        Assert-DockerDesktopImageCapacity -EstimatedWriteBytes ([int64]10GB) `
            -SettingsFile $settings -DefaultFolder $default -OverrideFolder ''
        throw 'A full Docker Desktop image disk was accepted'
    } catch {
        if ($_.Exception.Message -notlike '*needs at least*') { throw }
    }
    $split = @(Get-LocalInstallVolumeRequirements -WslDiskPath 'C:\wsl\ext4.vhdx' `
        -DockerDiskPath 'D:\docker\docker_data.vhdx' -DatabaseDiskPath 'E:\db\ctf-agent-db.vhdx' `
        -ImageWorkBytes 10GB)
    if ($split.Count -ne 3 -or $split[0].RequiredFreeBytes -ne 6GB -or
        $split[1].RequiredFreeBytes -ne 15GB -or $split[2].RequiredFreeBytes -ne 6GB) {
        throw 'Separate backing drives incorrectly share or duplicate planned writes'
    }
    $shared = @(Get-LocalInstallVolumeRequirements -WslDiskPath 'C:\wsl\ext4.vhdx' `
        -DockerDiskPath 'c:\docker\docker_data.vhdx' -DatabaseDiskPath 'C:\db\ctf-agent-db.vhdx' `
        -ImageWorkBytes 10GB)
    if ($shared.Count -ne 1 -or $shared[0].RequiredFreeBytes -ne 17GB) {
        throw 'A shared backing drive did not combine planned writes'
    }
    $extended = @(Get-LocalInstallVolumeRequirements `
        -WslDiskPath '\\?\C:\wsl\ext4.vhdx' `
        -DockerDiskPath 'C:\docker\docker_data.vhdx' `
        -DatabaseDiskPath '\\?\C:\db\ctf-agent-db.vhdx' -ImageWorkBytes 10GB)
    if ($extended.Count -ne 1 -or $extended[0].Root -ne 'C:\' -or
        $extended[0].RequiredFreeBytes -ne 17GB) {
        throw 'Extended-length and normal paths on one Windows drive were counted separately'
    }
    $script:mockFree = [int64]17GB
    Assert-LocalInstallVolumeCapacity -WslDiskPath 'C:\wsl\ext4.vhdx' `
        -DockerDiskPath 'C:\docker\docker_data.vhdx' -DatabaseDiskPath 'C:\db\ctf-agent-db.vhdx' `
        -ImageWorkBytes 10GB | Out-Null
    $script:mockFree = [int64]17GB - 1
    try {
        Assert-LocalInstallVolumeCapacity -WslDiskPath 'C:\wsl\ext4.vhdx' `
            -DockerDiskPath 'C:\docker\docker_data.vhdx' -DatabaseDiskPath 'C:\db\ctf-agent-db.vhdx' `
            -ImageWorkBytes 10GB | Out-Null
        throw 'A shared backing drive below its combined boundary was accepted'
    } catch {
        if ($_.Exception.Message -notlike '*planned application, image and database writes*') { throw }
    }
    $script:mockFree = [int64]5GB - 1
    $warnings = @(Warn-LocalStartVolumeCapacity -WslDiskPath 'C:\wsl\ext4.vhdx' `
        -DockerDiskPath 'C:\docker\docker_data.vhdx' `
        -DatabaseDiskPath 'C:\db\ctf-agent-db.vhdx' 3>&1)
    if ($warnings.Count -ne 1 -or [string]$warnings[0] -notlike '*startup will continue*') {
        throw 'Low Windows free space blocked existing-service startup instead of warning'
    }
    function Get-DesktopDockerCli { return 'docker.exe' }
    $script:localDigestListing = ''
    $script:localRevision = ''
    function Invoke-DesktopNative([string]$file, [string[]]$arguments, [int]$timeoutSeconds) {
        if ($arguments -contains 'ls') {
            return [pscustomobject]@{ExitCode=0;Stdout=$script:localDigestListing}
        }
        return [pscustomobject]@{ExitCode=0;Stdout=$script:localRevision}
    }
    $revision = 'a' * 40
    if ((Get-EstimatedImageWorkBytes $revision) -ne 10GB) {
        throw 'An overlay without its public base digest was treated as cached'
    }
    $script:localDigestListing = 'ghcr.io/udonsari0101/ctf-agent-public sha256:' + ('b' * 64)
    $script:localRevision = $revision
    if ((Get-EstimatedImageWorkBytes $revision) -ne 2GB) {
        throw 'An exact cached public base digest was treated as a cold pull'
    }
    Remove-Item -LiteralPath $customDisk
    try {
        Resolve-DockerDesktopDiskFile -SettingsFile $settings -DefaultFolder $default -OverrideFolder '' | Out-Null
        throw 'Missing configured Docker Desktop image disk was accepted'
    } catch {
        if ($_.Exception.Message -notlike '*Cannot locate Docker Desktop image disk*') { throw }
    }
    'Docker Desktop image disk, shared-volume planning and cache checks passed'
} finally {
    # Only the exact dedicated test directory under RUNNER_TEMP is removed.
    $resolved = [IO.Path]::GetFullPath($root)
    $base = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if ($resolved.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
