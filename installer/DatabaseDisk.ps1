param([string]$ElevatedPayload = '')

$ErrorActionPreference = 'Stop'
function Get-DatabaseMountPath { return '/mnt/wsl/ctf-agent-db' }
function Get-DatabaseTaskName { return 'CTF Agent Database Mount' }
function Get-DatabaseDiskHelperPath {
    return (Join-Path $PSScriptRoot 'DatabaseDisk.ps1')
}

function Invoke-DatabaseNative([string]$file, [string[]]$arguments, [switch]$Quiet) {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($Quiet) { & $file @arguments *> $null }
        else { & $file @arguments | Out-Host }
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    return [int]$exitCode
}

function Invoke-DatabaseRootTool([string]$distro, [string]$tool, [string[]]$arguments = @()) {
    # WSL --exec resolves a bare program before the root user's usual shell
    # PATH is applied. Explicit env also covers tools in /usr/sbin and /sbin.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& wsl.exe --distribution $distro --user root --exec /usr/bin/env `
            'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' `
            $tool @arguments 2>&1 | ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    return [pscustomobject]@{ExitCode=$exitCode;Output=$output}
}

function Assert-DatabaseVhdPath([string]$path, [bool]$allowExisting = $true) {
    if (-not $path -or $path -notmatch '^[A-Za-z]:[\\/]' -or
        $path -match '[\x00-\x1f"<>|?*]' -or $path -match '(^|[\\/])\.\.([\\/]|$)') {
        throw 'Enter a full path on a local Windows drive for the database VHDX.'
    }
    # DiskPart script parsing is not dependable for non-ASCII file names.
    if ($path -match '[^\x20-\x7e]') {
        throw 'Use ASCII characters for the VHDX folder and file name.'
    }
    $full = [IO.Path]::GetFullPath($path)
    $windowsDirectory = $env:WINDIR.TrimEnd('\') + '\'
    if ($full.StartsWith($windowsDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Choose a VHDX folder outside the Windows system directory.'
    }
    if ([IO.Path]::GetExtension($full) -ine '.vhdx') {
        throw 'The database disk file must end in .vhdx.'
    }
    $root = [IO.Path]::GetPathRoot($full)
    if (-not $root -or $full.TrimEnd('\\') -eq $root.TrimEnd('\\')) {
        throw 'Choose a VHDX file inside a local drive folder.'
    }
    $drive = [IO.DriveInfo]::new($root)
    if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'The database VHDX needs a ready, fixed local drive.'
    }
    $cursor = Split-Path -Parent $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'The database disk folder must not be a link or a file.'
            }
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    if ((Test-Path -LiteralPath $full) -and -not $allowExisting) {
        throw 'That VHDX already exists. Choose a new file; existing disks are never formatted.'
    }
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'The database VHDX path is not a regular file.'
        }
    }
    return $full
}

function Resolve-DatabaseVhdInputPath([string]$path) {
    $candidate = $path.Trim()
    if ($candidate.Length -ge 2 -and $candidate.StartsWith('"') -and
        $candidate.EndsWith('"')) {
        $candidate = $candidate.Substring(1, $candidate.Length - 2)
    }
    if ($candidate -notmatch '^[A-Za-z]:[\\/]') {
        throw 'Enter a full folder or .vhdx path on a local Windows drive.'
    }
    if ([IO.Path]::GetExtension($candidate) -ine '.vhdx') {
        $candidate = [IO.Path]::Combine($candidate, 'ctf-agent-db.vhdx')
    }
    return (Assert-DatabaseVhdPath $candidate)
}

function Assert-DatabaseVhdHeader([string]$path) {
    $full = Assert-DatabaseVhdPath $path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'The database VHDX is missing.' }
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $buffer = New-Object byte[] 8
        if ($stream.Read($buffer, 0, 8) -ne 8 -or
            [Text.Encoding]::ASCII.GetString($buffer) -ne 'vhdxfile') {
            throw 'The selected file is not a VHDX disk.'
        }
    } finally { $stream.Dispose() }
    return $full
}

function Get-DatabaseMountInfo([string]$distro) {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& wsl.exe --distribution $distro --exec findmnt -rn -M (Get-DatabaseMountPath) -o SOURCE,FSTYPE 2>$null)
        if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1) { return $null }
        $parts = @($lines[0].Trim() -split '\s+')
        if ($parts.Count -ne 2 -or $parts[1] -ne 'ext4' -or $parts[0] -notmatch '^/dev/[A-Za-z0-9]+$') {
            throw 'The database mount is not a standalone ext4 disk.'
        }
        $uuidResult = Invoke-DatabaseRootTool $distro 'blkid' @('-s', 'UUID', '-o', 'value', $parts[0])
        $uuidLines = @($uuidResult.Output)
        if ($uuidResult.ExitCode -ne 0 -or $uuidLines.Count -ne 1 -or
            $uuidLines[0].Trim() -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
            throw 'The database filesystem identity could not be verified.'
        }
        return [pscustomobject]@{ Source = $parts[0]; Uuid = $uuidLines[0].Trim().ToLowerInvariant() }
    } finally { $ErrorActionPreference = $previousPreference }
}

function Invoke-ElevatedDatabaseAction([string]$action, [string]$vhd, [string]$userSid = '') {
    $full = Assert-DatabaseVhdPath $vhd
    if ($action -notin @('create-bare', 'mount', 'unmount', 'register-task', 'unregister-task')) {
        throw 'Unsupported database disk action.'
    }
    if (-not $userSid) { $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
        (@{action=$action;vhd=$full;sid=$userSid} | ConvertTo-Json -Compress)))
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        & (Get-DatabaseDiskHelperPath) -ElevatedPayload $payload
        return
    }
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Get-DatabaseDiskHelperPath) + '" -ElevatedPayload ' + $payload
    try {
        $process = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs `
            -WindowStyle Hidden -Wait -PassThru
    } catch {
        throw "Administrator access is required to $action the database disk."
    }
    if ($process.ExitCode -ne 0) { throw "Could not $action the database disk (exit code $($process.ExitCode))." }
}

function Test-DatabaseMount([string]$distro, [string]$expectedUuid) {
    $info = Get-DatabaseMountInfo $distro
    if (-not $info) { return $false }
    if ($expectedUuid -and $info.Uuid -ne $expectedUuid.ToLowerInvariant()) {
        throw 'A different filesystem is mounted at the CTF Agent database path.'
    }
    return $true
}

function Resolve-DatabaseTaskSid([string]$identity) {
    if ($identity -match '^S-1-5-') { return $identity }
    try {
        $account = New-Object Security.Principal.NTAccount -ArgumentList @($identity)
        return $account.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { return '' }
}

function Test-DatabaseMountTask([string]$vhd, [string]$sid) {
    $task = Get-ScheduledTask -TaskName (Get-DatabaseTaskName) -ErrorAction SilentlyContinue
    if (-not $task) { return $false }
    $execute = Join-Path $env:WINDIR 'System32\wsl.exe'
    $arguments = '--mount --vhd "' + (Assert-DatabaseVhdPath $vhd) + '" --name ctf-agent-db'
    return ($task.Actions.Count -eq 1 -and
        $task.Actions[0].Execute -ieq $execute -and
        $task.Actions[0].Arguments -eq $arguments -and
        (Resolve-DatabaseTaskSid ([string]$task.Principal.UserId)) -eq $sid -and
        [string]$task.Principal.RunLevel -eq 'Highest' -and
        @($task.Triggers | Where-Object {
            $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and
            (Resolve-DatabaseTaskSid ([string]$_.UserId)) -eq $sid
        }).Count -ge 1)
}

function Ensure-DatabaseMount([string]$distro, [string]$vhd,
    [string]$uuid, [bool]$taskManaged) {
    $full = Assert-DatabaseVhdPath $vhd
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'The configured database VHDX file is missing.'
    }
    $alreadyMounted = Test-DatabaseMount $distro $uuid
    if ($alreadyMounted) {
        # Windows can hold an attached VHDX exclusively. Check its header
        # when readable; the mounted ext4 UUID and marker remain authoritative.
        try { Assert-DatabaseVhdHeader $full | Out-Null }
        catch [System.IO.IOException] { }
    }
    if (-not $alreadyMounted) {
        if ($taskManaged) {
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if (-not (Test-DatabaseMountTask $vhd $sid)) {
                throw 'The database auto-mount task is missing or changed.'
            }
            try { Start-ScheduledTask -TaskName (Get-DatabaseTaskName) }
            catch { Write-Warning 'The scheduled mount could not be started; an administrator prompt may be needed.' }
            for ($attempt = 0; $attempt -lt 30; $attempt++) {
                if (Test-DatabaseMount $distro $uuid) { break }
                Start-Sleep -Seconds 1
            }
            if (-not (Test-DatabaseMount $distro $uuid)) {
                # A manually launched Start.cmd can recover when Windows
                # denies non-elevated Start-ScheduledTask for a highest task.
                $taskInfo = Get-ScheduledTaskInfo -TaskName (Get-DatabaseTaskName) -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-Warning "Database mount task result: $($taskInfo.LastTaskResult). Trying an administrator prompt."
                }
                try { Invoke-ElevatedDatabaseAction 'mount' $vhd }
                catch {
                    if (-not (Test-DatabaseMount $distro $uuid)) { throw }
                }
                if (-not (Test-DatabaseMount $distro $uuid)) {
                    throw 'The database VHDX did not mount with its recorded identity.'
                }
            }
        } else {
            Invoke-ElevatedDatabaseAction 'mount' $vhd
            if (-not (Test-DatabaseMount $distro $uuid)) {
                throw 'The database VHDX did not mount with its recorded identity.'
            }
        }
    }
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $marker = @(& wsl.exe --distribution $distro --exec cat "$(Get-DatabaseMountPath)/.ctf-agent-db-volume" 2>$null)
        $markerExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($markerExit -ne 0 -or $marker.Count -ne 1 -or
        $marker[0].Trim() -ne $uuid.Replace('-', '').ToLowerInvariant()) {
        throw 'The database volume marker is missing or does not match.'
    }
}

function Ensure-DatabaseBindLink([string]$distro, [string]$linuxHome,
    [string]$databasePath, [switch]$AllowCreateDatabaseDirectory) {
    # Docker Desktop can route a /mnt/wsl source through its host-file proxy,
    # which may show an old, detached VHD. An exact symlink inside the Ubuntu
    # home makes Docker use its WSL-distribution file proxy instead. The Linux
    # launcher still verifies that both sides see the same live database.
    $program = @'
import os,pathlib,sys
home=pathlib.Path(sys.argv[1])
database=pathlib.Path(sys.argv[2])
allow_create=sys.argv[3]=="true"
if (not home.is_absolute() or str(home)=="/" or home.is_symlink()
        or database!=pathlib.Path("/mnt/wsl/ctf-agent-db/Database/CTF_Agent")
        or database.is_symlink() or database.parent.is_symlink()):
    raise SystemExit("Invalid external database bind path")
home.mkdir(parents=True,exist_ok=True)
if not home.is_dir() or home.is_symlink():
    raise SystemExit("The application data directory is unavailable")
if not database.is_dir():
    if not allow_create or database.exists():
        raise SystemExit("The external database directory is unavailable")
    database.mkdir(parents=True, exist_ok=False)
link=home/".database-bind"
if link.is_symlink():
    if os.readlink(link)!=str(database):
        raise SystemExit("The database bind link points elsewhere")
elif link.exists():
    raise SystemExit("The database bind path is occupied")
else:
    os.symlink(str(database),link)
if not link.is_symlink() or os.readlink(link)!=str(database) or not link.is_dir():
    raise SystemExit("The database bind link is unavailable")
print(link)
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($program))
    $wrapper = 'import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))'
    $result = Invoke-DesktopNative 'wsl.exe' @('--distribution', $distro, '--exec',
        'python3', '-c', $wrapper, $encoded, $linuxHome, $databasePath,
        $AllowCreateDatabaseDirectory.IsPresent.ToString().ToLowerInvariant()) 15
    $expected = "$linuxHome/.database-bind"
    if ($result.ExitCode -ne 0 -or $result.Stdout.Trim() -ne $expected) {
        throw "The external database bind link could not be verified: $($result.Output)"
    }
    return $expected
}

function Invoke-DatabaseElevatedPayload([string]$payload) {
    $request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
    $action = [string]$request.action
    $vhd = Assert-DatabaseVhdPath ([string]$request.vhd)
    $sid = [string]$request.sid
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator access is required to manage the database disk.'
    }
    if (-not $sid -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $sid) {
        throw 'UAC used a different Windows account. Sign in with an administrator account to use a separate database VHDX.'
    }
    if ($action -eq 'create-bare') {
        $vhd = Assert-DatabaseVhdPath $vhd $false
        $parent = Split-Path -Parent $vhd
        [IO.Directory]::CreateDirectory($parent) | Out-Null
        $vhd = Assert-DatabaseVhdPath $vhd $false
        $scriptPath = Join-Path $env:TEMP ("ctf-agent-db-" + [Guid]::NewGuid().ToString('N') + '.txt')
        try {
            @(
                ('create vdisk file="' + $vhd + '" maximum=65536 type=expandable')
                'exit'
            ) |
                Set-Content -LiteralPath $scriptPath -Encoding ASCII
            $exitCode = Invoke-DatabaseNative 'diskpart.exe' @('/s', $scriptPath) -Quiet
            if ($exitCode -ne 0) { throw 'DiskPart could not create the VHDX.' }
        } finally { Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue }
        Assert-DatabaseVhdHeader $vhd | Out-Null
        $exitCode = Invoke-DatabaseNative 'wsl.exe' @('--mount', '--vhd', $vhd, '--bare')
        if ($exitCode -ne 0) { throw 'WSL could not attach the new VHDX.' }
        return
    }
    if ($action -eq 'mount') {
        Assert-DatabaseVhdHeader $vhd | Out-Null
        $exitCode = Invoke-DatabaseNative 'wsl.exe' @('--mount', '--vhd', $vhd,
            '--name', 'ctf-agent-db')
        if ($exitCode -ne 0) { throw 'WSL could not mount the database VHDX.' }
        return
    }
    if ($action -eq 'unmount') {
        $exitCode = Invoke-DatabaseNative 'wsl.exe' @('--unmount', $vhd)
        if ($exitCode -ne 0) { throw 'WSL could not detach the database VHDX.' }
        return
    }
    if ($action -notin @('register-task', 'unregister-task')) { throw 'Unsupported database disk action.' }
    if ($sid -notmatch '^S-1-5-') { throw 'Invalid Windows account identity.' }
    $execute = Join-Path $env:WINDIR 'System32\wsl.exe'
    $arguments = '--mount --vhd "' + $vhd + '" --name ctf-agent-db'
    $existing = Get-ScheduledTask -TaskName (Get-DatabaseTaskName) -ErrorAction SilentlyContinue
    if ($existing) {
        if (-not (Test-DatabaseMountTask $vhd $sid)) {
            throw 'An unrelated scheduled task uses the CTF Agent database name.'
        }
        if ($action -eq 'register-task') { return }
        Unregister-ScheduledTask -TaskName (Get-DatabaseTaskName) -Confirm:$false
        return
    }
    if ($action -eq 'unregister-task') { return }
    $taskAction = New-ScheduledTaskAction -Execute $execute -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName (Get-DatabaseTaskName) -Action $taskAction -Trigger $trigger `
        -Principal $taskPrincipal -Settings $settings | Out-Null
}

if ($ElevatedPayload) { Invoke-DatabaseElevatedPayload $ElevatedPayload }
