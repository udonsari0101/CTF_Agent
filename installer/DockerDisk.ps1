# Docker Desktop stores pulled images in its own Windows-backed WSL disk.
# Checking the selected Ubuntu distribution alone misses this separate volume.
function Resolve-DockerDesktopDiskFile {
    param(
        [string]$SettingsFile = (Join-Path $env:APPDATA 'Docker\settings-store.json'),
        [string]$DefaultFolder = (Join-Path $env:LOCALAPPDATA 'Docker\wsl'),
        [string]$OverrideFolder = $env:CTF_AGENT_DOCKER_DATA_ROOT
    )

    if ($OverrideFolder) {
        $folder = [Environment]::ExpandEnvironmentVariables($OverrideFolder)
    } elseif (Test-Path -LiteralPath $SettingsFile -PathType Leaf) {
        try {
            $settings = Get-Content -LiteralPath $SettingsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            throw 'Cannot read Docker Desktop disk settings. Check Settings > Resources > Advanced.'
        }
        $configured = [string]$settings.dataFolder
        $folder = if ($configured) {
            [Environment]::ExpandEnvironmentVariables($configured)
        } else { $DefaultFolder }
    } else {
        $folder = $DefaultFolder
    }
    if ($folder -notmatch '^[A-Za-z]:[\\/]') {
        throw 'Docker Desktop image disk must be on a local Windows drive.'
    }
    $candidates = if ($folder -match '\.vhdx$') { @($folder) } else { @(
        (Join-Path $folder 'docker_data.vhdx'),
        (Join-Path $folder 'disk\docker_data.vhdx'),
        (Join-Path $folder 'data\docker_data.vhdx'),
        (Join-Path $folder 'data\ext4.vhdx')
    ) }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw ('Cannot locate Docker Desktop image disk under {0}. Check Settings > Resources > Advanced, or set CTF_AGENT_DOCKER_DATA_ROOT to its disk image folder.' -f $folder)
}

function Assert-DockerDesktopImageCapacity {
    param(
        [int64]$EstimatedWriteBytes,
        [string]$SettingsFile = (Join-Path $env:APPDATA 'Docker\settings-store.json'),
        [string]$DefaultFolder = (Join-Path $env:LOCALAPPDATA 'Docker\wsl'),
        [string]$OverrideFolder = $env:CTF_AGENT_DOCKER_DATA_ROOT
    )
    $disk = Resolve-DockerDesktopDiskFile -SettingsFile $SettingsFile `
        -DefaultFolder $DefaultFolder -OverrideFolder $OverrideFolder
    $free = Get-HostVolumeFree $disk
    $required = [int64]5GB + $EstimatedWriteBytes
    Write-Host ('Docker Desktop image disk: {0}; Windows volume free: {1:N1} GiB' -f $disk, ($free / 1GB))
    if ($free -lt $required) {
        throw ('Docker Desktop image disk needs at least {0:g} GiB free before the image pull to leave 5 GiB after estimated writes.' -f ($required / 1GB))
    }
}
