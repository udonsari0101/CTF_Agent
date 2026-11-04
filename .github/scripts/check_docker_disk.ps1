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
    Remove-Item -LiteralPath $customDisk
    try {
        Resolve-DockerDesktopDiskFile -SettingsFile $settings -DefaultFolder $default -OverrideFolder '' | Out-Null
        throw 'Missing configured Docker Desktop image disk was accepted'
    } catch {
        if ($_.Exception.Message -notlike '*Cannot locate Docker Desktop image disk*') { throw }
    }
    'Docker Desktop image disk detection and 5 GiB boundary checks passed'
} finally {
    # Only the exact dedicated test directory under RUNNER_TEMP is removed.
    $resolved = [IO.Path]::GetFullPath($root)
    $base = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if ($resolved.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
