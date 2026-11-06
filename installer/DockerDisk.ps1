# Docker Desktop stores pulled images in its own Windows-backed WSL disk.
# Checking the selected Ubuntu distribution alone misses this separate volume.
function Get-HostVolumeFree([string]$path) {
    $expanded = [Environment]::ExpandEnvironmentVariables($path)
    if ($expanded -match '^\\\\\?\\[A-Za-z]:\\') { $expanded = $expanded.Substring(4) }
    if ($expanded -match '^[A-Za-z]:$') { $expanded += '\' }
    $root = [IO.Path]::GetPathRoot($expanded)
    if (-not $root -or $root.StartsWith('\\')) { throw "Cannot check the Windows volume for $path" }
    return [int64](Get-PSDrive -Name $root.Substring(0, 1) -ErrorAction Stop).Free
}

function Get-WslDiskHostPath([string]$distro) {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    $registered = @(Get-ChildItem -Path $key -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty -Path $_.PSPath } |
        Where-Object { $_.DistributionName -eq $distro } | Select-Object -First 1)
    if (-not $registered.Count -or -not $registered[0].BasePath) {
        throw 'Could not locate the selected WSL disk on Windows.'
    }
    return [string]$registered[0].BasePath
}

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

function Get-EstimatedImageWorkBytes([string]$revision) {
    # A local overlay with the requested revision does not prove that the
    # published base digest is still cached. Pruning may have removed the
    # base reference, so use the 2 GiB estimate only for a verified local
    # public-image digest whose revision label matches this release.
    if ($revision -notmatch '^[0-9a-f]{40}$') { return [int64]10GB }
    $docker = Get-DesktopDockerCli
    $repository = 'ghcr.io/udonsari0101/ctf-agent-public'
    $listed = Invoke-DesktopNative $docker @('--context', 'desktop-linux',
        'image', 'ls', '--digests', '--format={{.Repository}} {{.Digest}}') 8
    if ($listed.ExitCode -ne 0) { return [int64]10GB }
    foreach ($line in @($listed.Stdout -split "`n")) {
        $parts = @($line.Trim() -split '\s+')
        if ($parts.Count -ne 2 -or $parts[0] -ne $repository -or
            $parts[1] -notmatch '^sha256:[0-9a-f]{64}$') { continue }
        $image = "$repository@$($parts[1])"
        $checked = Invoke-DesktopNative $docker @('--context', 'desktop-linux',
            'image', 'inspect', $image,
            '--format={{index .Config.Labels "org.opencontainers.image.revision"}}') 8
        if ($checked.ExitCode -eq 0 -and $checked.Stdout.Trim() -eq $revision) {
            return [int64]2GB
        }
    }
    return [int64]10GB
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

# A WSL distribution, Docker Desktop and a separate database VHDX can all
# expand on the same Windows drive. Independent checks of each disk would
# count the same free bytes more than once. Aggregate their planned writes by
# physical drive before the first pull or VHDX initialization.
function Get-LocalInstallVolumeRequirements {
    param(
        [Parameter(Mandatory=$true)][string]$WslDiskPath,
        [Parameter(Mandatory=$true)][string]$DockerDiskPath,
        [string]$DatabaseDiskPath = '',
        [int64]$ApplicationWorkBytes = 1GB,
        [int64]$ImageWorkBytes = 10GB,
        [int64]$DatabaseWorkBytes = 1GB,
        [int64]$MinimumFreeBytes = 5GB
    )
    foreach ($amount in @($ApplicationWorkBytes, $ImageWorkBytes,
            $DatabaseWorkBytes, $MinimumFreeBytes)) {
        if ($amount -lt 0) { throw 'Planned disk writes must be non-negative.' }
    }
    $planned = @{}
    $paths = @(
        @{Path=$WslDiskPath;Bytes=$ApplicationWorkBytes},
        @{Path=$DockerDiskPath;Bytes=$ImageWorkBytes}
    )
    if ($DatabaseDiskPath) {
        $paths += @{Path=$DatabaseDiskPath;Bytes=$DatabaseWorkBytes}
    }
    foreach ($item in $paths) {
        $path = [Environment]::ExpandEnvironmentVariables([string]$item.Path)
        # WSL registrations can use an extended-length drive path. Count it
        # against the same Windows volume as the ordinary drive-letter form.
        if ($path.StartsWith('\\?\', [StringComparison]::Ordinal) -and
            $path.Substring(4) -match '^[A-Za-z]:[\\/]') {
            $path = $path.Substring(4)
        }
        $root = [IO.Path]::GetPathRoot($path)
        if ($root -notmatch '^[A-Za-z]:[\\/]$') {
            throw 'The selected storage disk is not on a local Windows drive.'
        }
        $root = $root.Substring(0, 1).ToUpperInvariant() + ':\'
        if (-not $planned.ContainsKey($root)) { $planned[$root] = [int64]0 }
        $planned[$root] = [int64]$planned[$root] + [int64]$item.Bytes
    }
    foreach ($root in @($planned.Keys | Sort-Object)) {
        [pscustomobject]@{
            Root = $root
            PlannedWriteBytes = [int64]$planned[$root]
            RequiredFreeBytes = [int64]$MinimumFreeBytes + [int64]$planned[$root]
        }
    }
}

function Assert-LocalInstallVolumeCapacity {
    param(
        [Parameter(Mandatory=$true)][string]$WslDiskPath,
        [Parameter(Mandatory=$true)][string]$DockerDiskPath,
        [string]$DatabaseDiskPath = '',
        [int64]$ApplicationWorkBytes = 1GB,
        [int64]$ImageWorkBytes = 10GB,
        [int64]$DatabaseWorkBytes = 1GB,
        [int64]$MinimumFreeBytes = 5GB
    )
    $plan = @(Get-LocalInstallVolumeRequirements `
        -WslDiskPath $WslDiskPath -DockerDiskPath $DockerDiskPath `
        -DatabaseDiskPath $DatabaseDiskPath -ApplicationWorkBytes $ApplicationWorkBytes `
        -ImageWorkBytes $ImageWorkBytes -DatabaseWorkBytes $DatabaseWorkBytes `
        -MinimumFreeBytes $MinimumFreeBytes)
    foreach ($item in $plan) {
        $free = Get-HostVolumeFree $item.Root
        if ($free -lt $item.RequiredFreeBytes) {
            throw ('Drive {0} needs {1:g} GiB free for the planned application, image and database writes while leaving 5 GiB unused.' -f `
                $item.Root, ($item.RequiredFreeBytes / 1GB))
        }
    }
    return $plan
}

function Warn-LocalStartVolumeCapacity {
    param(
        [Parameter(Mandatory=$true)][string]$WslDiskPath,
        [Parameter(Mandatory=$true)][string]$DockerDiskPath,
        [string]$DatabaseDiskPath = ''
    )
    # Starting an installed service does not pull an image or initialize a
    # disk. Leave the 5 GiB reserve enforced for new writes, but do not make
    # low host space prevent the operator from starting an existing service.
    try {
        Assert-LocalInstallVolumeCapacity -WslDiskPath $WslDiskPath `
            -DockerDiskPath $DockerDiskPath -DatabaseDiskPath $DatabaseDiskPath `
            -ApplicationWorkBytes 0 -ImageWorkBytes 0 -DatabaseWorkBytes 0 | Out-Null
    } catch {
        Write-Warning ('Windows storage reserve could not be verified or is below 5 GiB; startup will continue. ' + $_.Exception.Message)
    }
}
