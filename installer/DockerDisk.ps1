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
        # WSL 2 installs keep a moved disk in CustomWslDistroDir, which is what
        # Settings > Resources > Advanced > Disk image location writes.
        $configured = [string]$settings.CustomWslDistroDir
        if (-not $configured) { $configured = [string]$settings.dataFolder }
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
    # Only the digest currently published for this exact revision can be
    # treated as cached. A different local digest can carry the same revision
    # label and would still require a cold pull.
    # A cold install stores the compressed layers, one unpacked copy from the
    # pull and a second unpacked copy in the build cache of the local overlay.
    # v0.4.57 grew an empty Docker Desktop disk to 17.2 GB.
    if ($revision -notmatch '^[0-9a-f]{40}$') { return [int64]18GB }
    $docker = Get-DesktopDockerCli
    $repository = 'ghcr.io/udonsari0101/ctf-agent-public'
    $manifest = Invoke-DesktopNative $docker @('--context', 'desktop-linux',
        'manifest', 'inspect', '--verbose', "$repository`:$revision") 30
    if ($manifest.ExitCode -ne 0) { return [int64]18GB }
    try {
        $published = $manifest.Stdout | ConvertFrom-Json -ErrorAction Stop
        $digest = [string]$published.Descriptor.digest
    } catch { return [int64]18GB }
    if ($digest -notmatch '^sha256:[0-9a-f]{64}$') { return [int64]18GB }
    $image = "$repository@$digest"
    $checked = Invoke-DesktopNative $docker @('--context', 'desktop-linux',
        'image', 'inspect', $image,
        '--format={{index .Config.Labels "org.opencontainers.image.revision"}}') 8
    if ($checked.ExitCode -eq 0 -and $checked.Stdout.Trim() -eq $revision) {
        return [int64]10GB
    }
    return [int64]18GB
}

function Select-DockerDiskFolder([string]$currentDisk, [int64]$requiredBytes, [string]$preferredPath) {
    # Prefers the drive already chosen for the database, then the fixed NTFS
    # drive with the most room. Returns '' when no other drive can hold the disk.
    $needed = $requiredBytes + (Get-Item -LiteralPath $currentDisk).Length
    $currentDrive = ([IO.Path]::GetPathRoot($currentDisk)).Substring(0, 1)
    $preferredDrive = if ($preferredPath) { ([IO.Path]::GetPathRoot($preferredPath)).Substring(0, 1) } else { '' }
    $volume = @(Get-Volume | Where-Object {
        $_.DriveLetter -and [string]$_.DriveLetter -ine $currentDrive -and $_.DriveType -eq 'Fixed' -and
        $_.FileSystemType -eq 'NTFS' -and $_.SizeRemaining -ge $needed
    } | Sort-Object @{Expression={ [string]$_.DriveLetter -ieq $preferredDrive };Descending=$true},
        @{Expression='SizeRemaining';Descending=$true}) | Select-Object -First 1
    if (-not $volume) { return '' }
    return "$($volume.DriveLetter):\DockerDesktopData"
}

function Move-DockerDesktopDisk([string]$folder) {
    # Docker Desktop moves its disk only from its Settings window, so this
    # moves the file while Docker Desktop is stopped and records the new folder.
    if ($folder -notmatch '^[A-Za-z]:[\\/]') { throw 'The Docker Desktop disk folder must be on a local Windows drive.' }
    $source = Resolve-DockerDesktopDiskFile
    $target = Join-Path $folder 'disk\docker_data.vhdx'
    if (Test-Path -LiteralPath $target) { throw "A Docker Desktop disk already exists at $target." }
    if (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue) { Stop-DockerDesktopForSettings }
    for ($attempt = 0; ; $attempt++) {
        try {
            [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None).Dispose()
            break
        } catch [System.IO.IOException] {
            if ($attempt -ge 60) { throw 'WSL did not release the Docker Desktop disk.' }
            Start-Sleep -Seconds 1
        }
    }
    Write-Host "Moving Docker Desktop's disk to $target..."
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Move-Item -LiteralPath $source -Destination $target
    $file = Get-DockerDesktopSettingsFile
    $settings = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings | Add-Member -NotePropertyName 'CustomWslDistroDir' -NotePropertyValue $folder -Force
    Save-DockerDesktopSettings $file $settings
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
        [int64]$ImageWorkBytes = 18GB,
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
        [int64]$ImageWorkBytes = 18GB,
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
