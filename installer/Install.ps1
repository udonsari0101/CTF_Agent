param(
    # Install.cmd finishes without questions unless -Interactive is passed. The
    # other options are optional; saved settings and detected defaults fill in.
    [switch]$Interactive,
    [string]$Distribution = '',
    [string]$DataFolder = '',
    [string]$DatabaseFolder = '',
    [string]$DockerFolder = '',
    [ValidateSet('Existing', 'Install')][string]$DockerMode = '',
    [ValidateSet('', '127.0.0.1', '0.0.0.0')][string]$ListenAddress = '',
    [switch]$NoLogin,
    [switch]$StartAtSignIn,
    [string[]]$PublicUrl = @(),
    [switch]$OpenAccess
)

$ErrorActionPreference = 'Stop'
if ($env:CTF_AGENT_LAUNCH_MARKER) { [IO.File]::WriteAllText($env:CTF_AGENT_LAUNCH_MARKER, '') }
$installer = Join-Path $PSScriptRoot 'installer\install.sh'
$stateFile = Join-Path $env:LOCALAPPDATA 'CTF Agent\install.json'
$minimumFreeBytes = 5GB
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Release archive is incomplete.' }
$wslPreparation = Join-Path $PSScriptRoot 'installer\prepare-wsl.sh'
if (-not (Test-Path -LiteralPath $wslPreparation -PathType Leaf)) { throw 'Release archive is incomplete: prepare-wsl.sh is missing.' }
$databaseDiskHelper = Join-Path $PSScriptRoot 'DatabaseDisk.ps1'
if (-not (Test-Path -LiteralPath $databaseDiskHelper -PathType Leaf)) { throw 'Release archive is incomplete.' }
. $databaseDiskHelper
$dockerDesktopHelper = Join-Path $PSScriptRoot 'DockerDesktop.ps1'
if (-not (Test-Path -LiteralPath $dockerDesktopHelper -PathType Leaf)) { throw 'Release archive is incomplete: DockerDesktop.ps1 is missing.' }
. $dockerDesktopHelper
$dockerDiskHelper = Join-Path $PSScriptRoot 'DockerDisk.ps1'
if (-not (Test-Path -LiteralPath $dockerDiskHelper -PathType Leaf)) { throw 'Release archive is incomplete: DockerDisk.ps1 is missing.' }
. $dockerDiskHelper

function Ask-YesNo([string]$question, [bool]$default = $true) {
    if (-not $Interactive) {
        Write-Host "$question $(if ($default) { 'Yes' } else { 'No' })"
        return $default
    }
    $hint = if ($default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $answer = (Read-Host "$question [$hint]").Trim().ToLowerInvariant()
        if (-not $answer) { return $default }
        if ($answer -in @('y', 'yes')) { return $true }
        if ($answer -in @('n', 'no')) { return $false }
        Write-Host 'Enter Y or N.'
    }
}

function Read-TimedChoice([string]$question, [string]$default,
    [string[]]$choices, [int]$seconds = 30) {
    if ($default -notin $choices) { throw 'Invalid default choice.' }
    Write-Host "$question [$default] (default in $seconds seconds): " -NoNewline
    if ([Console]::IsInputRedirected) {
        Write-Host $default
        return $default
    }
    $inputText = ''
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        while ($watch.Elapsed.TotalSeconds -lt $seconds) {
            if (-not [Console]::KeyAvailable) {
                Start-Sleep -Milliseconds 100
                continue
            }
            $key = [Console]::ReadKey($true)
            $watch.Restart()
            if ($key.Key -eq [ConsoleKey]::Enter) {
                Write-Host ''
                if (-not $inputText) { return $default }
                if ($inputText -in $choices) { return $inputText }
                Write-Host 'Choose one of the displayed options.'
                return Read-TimedChoice $question $default $choices $seconds
            }
            if ($key.Key -eq [ConsoleKey]::Backspace) {
                if ($inputText) {
                    $inputText = $inputText.Substring(0, $inputText.Length - 1)
                    Write-Host "`b `b" -NoNewline
                }
                continue
            }
            if (-not [char]::IsControl($key.KeyChar)) {
                $inputText += [string]$key.KeyChar
                Write-Host $key.KeyChar -NoNewline
            }
        }
    } catch {
        # A detached console or redirected launcher must not block installation.
        Write-Host $default
        return $default
    }
    Write-Host "`nNo choice entered; using $default."
    return $default
}

function Get-InstallPublicUrls([string[]]$items) {
    $urls = @()
    foreach ($item in $items) {
        foreach ($piece in ([string]$item -split ',')) {
            $value = $piece.Trim()
            if (-not $value) { continue }
            $uri = $null
            if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -or
                $uri.Scheme -notin @('http', 'https') -or -not $uri.Host -or
                $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
                $uri.AbsolutePath -ne '/') {
                throw "PublicUrl must be an HTTP(S) origin without a path, query or credentials: $value"
            }
            $origin = $uri.GetLeftPart([UriPartial]::Authority).TrimEnd('/')
            if ($origin -notin $urls) { $urls += $origin }
        }
    }
    return $urls
}

function Convert-WslListBytes([byte[]]$bytes) {
    if (-not $bytes -or -not $bytes.Length) { return @() }
    $encoding = [Text.Encoding]::UTF8
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xff -and $bytes[1] -eq 0xfe) {
        $encoding = [Text.Encoding]::Unicode
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xfe -and $bytes[1] -eq 0xff) {
        $encoding = [Text.Encoding]::BigEndianUnicode
    } elseif ($bytes.Length -ge 4) {
        $evenNull = 0
        $oddNull = 0
        for ($index = 0; $index -lt [Math]::Min(80, $bytes.Length); $index++) {
            if ($bytes[$index] -eq 0) {
                if ($index % 2) { $oddNull++ } else { $evenNull++ }
            }
        }
        if ($oddNull -ge 2 -and $oddNull -gt ($evenNull * 2)) {
            $encoding = [Text.Encoding]::Unicode
        } elseif ($evenNull -ge 2 -and $evenNull -gt ($oddNull * 2)) {
            $encoding = [Text.Encoding]::BigEndianUnicode
        }
    }
    $decoded = $encoding.GetString($bytes).TrimStart([char]0xfeff)
    return @($decoded -split '\r?\n' | ForEach-Object {
        ($_ -replace "`0", '').TrimStart([char]0xfeff).TrimEnd("`r")
    } | Where-Object { $_.Trim() })
}

function Invoke-WslList([string]$mode) {
    if ($mode -notin @('quiet', 'verbose')) { throw 'Unsupported WSL list mode.' }
    $wslPath = Join-Path $env:WINDIR 'System32\wsl.exe'
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        $wslPath = Join-Path $env:WINDIR 'Sysnative\wsl.exe'
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $wslPath
    $start.Arguments = "--list --$mode"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $buffer = New-Object IO.MemoryStream
    try {
        $process.StandardOutput.BaseStream.CopyTo($buffer)
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $lines = @(Convert-WslListBytes $buffer.ToArray())
    } finally {
        $buffer.Dispose()
        $process.Dispose()
    }
    return [pscustomobject]@{ Lines=$lines; ExitCode=$exitCode; Error=$errorText }
}

function Get-WslNames {
    $listing = Invoke-WslList 'quiet'
    if ($listing.ExitCode -ne 0) {
        throw "WSL distribution listing failed (exit $($listing.ExitCode)). Retry Install.cmd as administrator under this same Windows account, then check wsl.exe --list --verbose."
    }
    return @($listing.Lines | ForEach-Object { $_.Trim().TrimStart([char]0xfeff) } |
        Where-Object { $_ -and $_ -notlike 'docker-desktop*' } | Select-Object -Unique)
}

function Get-WslVersions {
    $versions = @{}
    $listing = Invoke-WslList 'verbose'
    if ($listing.ExitCode -eq 0) {
        foreach ($line in $listing.Lines) {
            $clean = $line.Trim().TrimStart('*').Trim()
            if ($clean -match '^(.+?)\s{2,}.+?\s+([12])\s*$') {
                $versions[$Matches[1].Trim()] = [int]$Matches[2]
            }
        }
    } else {
        Write-Warning "WSL version listing failed (exit $($listing.ExitCode)); checking this Windows account's registered distributions."
    }
    # The per-user WSL registration resolves versions when localized list
    # formatting differs from the table above. It does not add hidden distros.
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    foreach ($entry in @(Get-ChildItem -Path $key -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty -Path $_.PSPath })) {
        $name = [string]$entry.DistributionName
        if ($name -and -not $versions.ContainsKey($name) -and
            $entry.Version -in @(1, 2)) {
            $versions[$name] = [int]$entry.Version
        }
    }
    if ($listing.ExitCode -ne 0 -and -not $versions.Count) {
        throw 'WSL version listing failed and no registered distributions were found. Retry Install.cmd as administrator under this same Windows account, then check wsl.exe --list --verbose.'
    }
    return $versions
}

function Invoke-WslPython([string]$name, [string]$source, [string[]]$arguments = @(), [switch]$ReadOnly) {
    # Windows PowerShell 5.1 changes quotes inside a multiline native argument.
    # Pass a single-line wrapper without quoted literals; Python decodes the
    # original source from a separate argument before forwarding its argv.
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
    $program = 'import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))'
    $nativeArguments = @('--distribution', $name, '--exec', 'python3', '-c', $program, $encoded) + $arguments
    $result = Invoke-DesktopNative 'wsl.exe' $nativeArguments 30
    if ($ReadOnly -and $result.TimedOut) {
        Write-Host 'A read-only WSL probe timed out. Retrying once...'
        $result = Invoke-DesktopNative 'wsl.exe' $nativeArguments 30
    }
    $detail = if ($result.ExitCode -ne 0) { $result.Output } else { $result.Stderr }
    return [pscustomobject]@{Output=$result.Stdout;ExitCode=$result.ExitCode;Error=$detail;TimedOut=$result.TimedOut}
}

function Invoke-WslPythonStdin([string]$name, [string]$source, [string[]]$arguments = @()) {
    # The WSL eligibility probe can use stdin if a particular Windows build
    # mishandles the Python -c argument through PowerShell 5.1.
    $previousPreference = $ErrorActionPreference
    $previousEncoding = $OutputEncoding
    try {
        $ErrorActionPreference = 'Continue'
        $OutputEncoding = New-Object Text.UTF8Encoding($false)
        $output = @($source | & wsl.exe --distribution $name --exec python3 - @arguments 2>$null)
        $exitCode = $LASTEXITCODE
    } finally {
        $OutputEncoding = $previousEncoding
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{ Output = ($output -join "`n"); ExitCode = $exitCode }
}

function Invoke-WslNative([string[]]$command, [switch]$Quiet, [switch]$Visible) {
    # Windows PowerShell 5.1 turns redirected native stderr into an ErrorRecord.
    # The caller must inspect the exit code, including when the WSL command is
    # missing while Docker Desktop is still starting.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($Quiet) {
            & wsl.exe @command *> $null
            $output = @()
        } elseif ($Visible) {
            & wsl.exe @command | Out-Host
            $output = @()
        } else {
            $output = @(& wsl.exe @command 2>$null)
        }
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{ Output=$output; ExitCode=$exitCode }
}

function Get-WslBlockDevices([string]$name) {
    $probe = @'
import json,subprocess
result=subprocess.run(['lsblk','-b','-J','-o','NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT'],
                      check=True,capture_output=True,text=True)
print(json.dumps(json.loads(result.stdout).get('blockdevices',[])))
'@
    $result = Invoke-WslPython $name $probe
    if ($result.ExitCode -ne 0) { throw 'Could not inspect WSL block devices; no disk was formatted.' }
    # In Windows PowerShell 5.1, wrapping ConvertFrom-Json's pipeline directly
    # nests the entire JSON array as one item. Return the decoded array itself.
    $devices = $result.Output | ConvertFrom-Json
    return $devices
}

function Assert-FreshDatabaseHome([string]$name, [string]$linuxDataHome) {
    $probe = @'
import json,os,sys
home=sys.argv[1]
db=os.path.join(home,'Database','CTF_Agent')
existing=os.path.lexists(os.path.join(home,'.current-release'))
occupied=os.path.lexists(db) and (os.path.islink(db) or
         not os.path.isdir(db) or bool(os.listdir(db)))
print(json.dumps({'installed':existing,'database_occupied':occupied}))
'@
    $result = Invoke-WslPython $name $probe @($linuxDataHome)
    if ($result.ExitCode -ne 0) { throw 'Could not check existing database data.' }
    $check = $result.Output | ConvertFrom-Json
    if ($check.installed -or $check.database_occupied) {
        throw 'An existing installation or database was found. Database relocation is not automatic; keep the original location.'
    }
}

function Assert-WslVhdSupport {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $helpText = (@(& wsl.exe --help 2>$null) -replace "`0", '') -join "`n"
    } finally { $ErrorActionPreference = $previousPreference }
    if ($helpText -notmatch '--mount' -or $helpText -notmatch '--vhd' -or
        $helpText -notmatch '--name') {
        throw 'This WSL version cannot mount a named VHDX. Update WSL and rerun Install.cmd.'
    }
}

function Select-DatabaseVhd([string]$savedPath, [string]$requestedPath = '') {
    if ($savedPath) {
        $savedPath = Assert-DatabaseVhdPath $savedPath
        if ($requestedPath -and
            (Assert-DatabaseVhdPath $requestedPath) -ine $savedPath) {
            throw 'The existing database VHDX cannot be relocated automatically. Keep its original path.'
        }
        Write-Host "Database VHDX: $savedPath"
        return $savedPath
    }
    if ($requestedPath) {
        $full = Assert-DatabaseVhdPath $requestedPath
    } else {
        $answer = (Read-Host 'Database folder or .vhdx path on a local Windows drive').Trim()
        if (-not $answer) { throw 'Enter a local drive path for the database VHDX.' }
        $full = Resolve-DatabaseVhdInputPath $answer
    }
    if ((Test-Path -LiteralPath $full) -and
        -not (Ask-YesNo 'Reuse this existing database VHDX after verifying its CTF Agent marker?' (-not $Interactive))) {
        throw 'Existing VHDX was left untouched. Choose a new file to create a new database.'
    }
    if ((Get-HostVolumeFree $full) -lt $minimumFreeBytes) {
        throw 'The database drive needs at least 5 GiB free before installation.'
    }
    return $full
}

function Read-DatabaseVolumeMarker([string]$name) {
    $probe = @'
import json,os,pathlib
p=pathlib.Path('/mnt/wsl/ctf-agent-db/.ctf-agent-db-volume')
if not p.is_file() or p.is_symlink() or p.stat().st_size > 128:
    print(json.dumps({'uuid':''}))
else:
    print(json.dumps({'uuid':p.read_text(encoding='ascii').strip()}))
'@
    $result = Invoke-WslPython $name $probe
    if ($result.ExitCode -ne 0) { throw "Could not verify the database volume marker (exit $($result.ExitCode)): $($result.Error)" }
    return [string](($result.Output | ConvertFrom-Json).uuid)
}

function Write-DatabaseVolumeMarker([string]$name, [string]$uuid) {
    $probe = @'
import os,pathlib,sys
p=pathlib.Path('/mnt/wsl/ctf-agent-db/.ctf-agent-db-volume')
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w',encoding='ascii') as stream:
    stream.write(sys.argv[1].replace('-','').lower()+'\n')
    stream.flush()
    os.fsync(stream.fileno())
'@
    $result = Invoke-WslPython $name $probe @($uuid)
    if ($result.ExitCode -ne 0) { throw 'Could not write the new database volume marker.' }
}

function Initialize-DatabaseVhd([string]$name, [string]$vhd, [string]$savedUuid) {
    Assert-WslVhdSupport
    $toolProbe = @'
import json,shutil
tools=['wipefs','mkfs.ext4','blkid','mount','mkdir','chown','chmod']
path='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
print(json.dumps({'missing':[tool for tool in tools if not shutil.which(tool,path=path)]}))
'@
    $toolResult = Invoke-WslPython $name $toolProbe -ReadOnly
    if ($toolResult.ExitCode -ne 0) { throw "Could not check database filesystem tools (exit $($toolResult.ExitCode)): $($toolResult.Error). No disk was created or formatted." }
    $missingTools = @((($toolResult.Output | ConvertFrom-Json).missing))
    if ($missingTools.Count) { throw "Missing database filesystem tools: $($missingTools -join ', '). Install util-linux and e2fsprogs in $name before retrying; no disk was created or formatted." }
    if ($savedUuid) {
        if (-not (Test-DatabaseMount $name $savedUuid)) {
            Assert-DatabaseVhdHeader $vhd | Out-Null
            Invoke-ElevatedDatabaseAction 'mount' $vhd
            if (-not (Test-DatabaseMount $name $savedUuid)) {
                throw 'The existing database VHDX did not mount with its recorded filesystem identity.'
            }
        }
        if ((Read-DatabaseVolumeMarker $name) -ne $savedUuid.Replace('-', '').ToLowerInvariant()) {
            throw 'The mounted database VHDX does not have its recorded CTF Agent marker.'
        }
        return $savedUuid.ToLowerInvariant()
    }
    $mountProbe = @'
import json,os,pathlib
p=pathlib.Path('/mnt/wsl/ctf-agent-db')
print(json.dumps({'unsafe':p.is_symlink() or (p.exists() and
                  (not p.is_dir() or bool(os.listdir(p))))}))
'@
    $mountResult = Invoke-WslPython $name $mountProbe
    if ($mountResult.ExitCode -ne 0 -or ($mountResult.Output | ConvertFrom-Json).unsafe) {
        throw 'The database mount directory already contains data; it was not overmounted.'
    }
    if (Test-Path -LiteralPath $vhd) {
        if (Get-DatabaseMountInfo $name) {
            throw 'A database filesystem is already mounted. Unmount it before adopting an existing VHDX without installation settings.'
        }
        # No database is mounted, so this only releases a bare attach left by
        # an interrupted run. Windows can hold an attached VHDX exclusively.
        Invoke-DesktopNative 'wsl.exe' @('--unmount', $vhd) 60 | Out-Null
        Assert-DatabaseVhdHeader $vhd | Out-Null
        if (Test-DatabaseVhdUnused $vhd) {
            Write-Host 'Recreating an empty database VHDX left by an interrupted installation.'
            Invoke-ElevatedDatabaseAction 'remove-unused' $vhd
        } else {
            Invoke-ElevatedDatabaseAction 'mount' $vhd
            $existing = Get-DatabaseMountInfo $name
            if (-not $existing -or (Read-DatabaseVolumeMarker $name) -ne $existing.Uuid.Replace('-', '')) {
                throw 'The existing VHDX is not a verified CTF Agent database volume; it was not formatted or changed.'
            }
            return $existing.Uuid
        }
    }
    if (Get-DatabaseMountInfo $name) {
        throw 'The CTF Agent database mount point is already in use.'
    }
    $before = @(Get-WslBlockDevices $name)
    Invoke-ElevatedDatabaseAction 'create-bare' $vhd
    $newDisk = @()
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $after = @(Get-WslBlockDevices $name)
        $names = @($before | ForEach-Object { [string]$_.name })
        $newDisk = @($after | Where-Object { [string]$_.name -notin $names })
        if ($newDisk.Count) { break }
        Start-Sleep -Seconds 1
    }
    if ($newDisk.Count -ne 1) {
        throw 'New VHDX block-device identity is ambiguous; no disk was formatted.'
    }
    foreach ($old in $before) {
        $same = @($after | Where-Object { $_.name -eq $old.name -and
            $_.size -eq $old.size -and $_.type -eq $old.type })
        if ($same.Count -ne 1) {
            throw 'An existing WSL block device changed during attach; no disk was formatted.'
        }
    }
    $disk = $newDisk[0]
    $device = '/dev/' + [string]$disk.name
    if ($disk.type -ne 'disk' -or $device -notmatch '^/dev/sd[a-z]+$' -or
        [math]::Abs(([int64]$disk.size) - [int64]64GB) -gt 1MB -or
        $disk.fstype -or $disk.mountpoint -or $disk.children) {
        throw 'The new block device is not an empty 64 GB VHDX; no disk was formatted.'
    }
    $signatureResult = Invoke-DatabaseRootTool $name 'wipefs' @('-n', $device)
    if ($signatureResult.ExitCode -ne 0) {
        throw "Could not inspect the new VHDX signatures: $($signatureResult.Output -join ' '). No disk was formatted."
    }
    $signatures = @($signatureResult.Output | Where-Object { $_.Trim() })
    if ($signatures.Count) {
        throw 'The new VHDX has an unexpected filesystem signature; no disk was formatted.'
    }
    $step = Invoke-DatabaseRootTool $name 'mkfs.ext4' @('-F', '-q', '-L', 'ctf-agent-db', $device)
    if ($step.ExitCode -ne 0) { throw "Could not format the verified new VHDX: $($step.Output -join ' ')" }
    $step = Invoke-DatabaseRootTool $name 'mkdir' @('-p', (Get-DatabaseMountPath))
    if ($step.ExitCode -ne 0) { throw "Could not create the WSL database mount point: $($step.Output -join ' ')" }
    $step = Invoke-DatabaseRootTool $name 'mount' @('-t', 'ext4', $device, (Get-DatabaseMountPath))
    if ($step.ExitCode -ne 0) { throw "Could not mount the new database filesystem: $($step.Output -join ' ')" }
    $info = Get-DatabaseMountInfo $name
    if (-not $info -or $info.Source -ne $device) {
        throw 'The formatted VHDX did not appear at the dedicated database mount point.'
    }
    $uidResult = Invoke-WslNative @('--distribution', $name, '--exec', 'id', '-u')
    $gidResult = Invoke-WslNative @('--distribution', $name, '--exec', 'id', '-g')
    if ($uidResult.ExitCode -ne 0 -or $gidResult.ExitCode -ne 0 -or
        @($uidResult.Output).Count -ne 1 -or @($gidResult.Output).Count -ne 1) {
        throw 'Could not determine the WSL user.'
    }
    $uid = [string]$uidResult.Output[0].Trim()
    $gid = [string]$gidResult.Output[0].Trim()
    if ($uid -notmatch '^\d+$' -or $gid -notmatch '^\d+$') { throw 'Could not determine the WSL user.' }
    $step = Invoke-DatabaseRootTool $name 'chown' @("$($uid):$gid", (Get-DatabaseMountPath))
    if ($step.ExitCode -ne 0) { throw 'Could not set database mount ownership.' }
    $step = Invoke-DatabaseRootTool $name 'chmod' @('0750', (Get-DatabaseMountPath))
    if ($step.ExitCode -ne 0) { throw 'Could not set database mount permissions.' }
    Write-DatabaseVolumeMarker $name $info.Uuid
    return $info.Uuid
}

function Get-WslCandidateInfo([string]$name, [hashtable]$versions) {
    # Listing a menu must not start every installed distro. On affected WSL
    # versions, an unselected systemd distro's idle shutdown removes shared
    # mounts used by Docker and by external DB VHDs (microsoft/WSL#41084).
    $version = if ($versions.ContainsKey($name)) { [int]$versions[$name] } else { 0 }
    $score = if ($version -ne 2) { 0 } elseif ($name -match 'Ubuntu') { 90 }
        elseif ($name -match 'Debian') { 80 } else { 60 }
    return [pscustomobject]@{Name=$name;Version=$version;Score=$score;
        Reason='WSL 2 required';Home='';Linux='not started';ProbeDeferred=$true}
}

function Get-WslInfo([string]$name, [hashtable]$versions) {
    $probe = @'
import json,os,pathlib,shutil,sys
data={}
try:
    for line in open('/etc/os-release',encoding='utf-8'):
        if '=' in line:
            key,value=line.rstrip('\n').split('=',1)
            data[key]=value.strip('"')
except OSError:
    pass
native_docker=False
for process in pathlib.Path('/proc').glob('[0-9]*/comm'):
    try:
        if process.read_text(encoding='ascii').strip()=='dockerd':
            native_docker=True
            break
    except (OSError,UnicodeError):
        pass
print(json.dumps({'id':data.get('ID',''),'version':data.get('VERSION_ID',''),
                  'home':os.path.expanduser('~'),'python':list(sys.version_info[:2]),
                  'bash':bool(shutil.which('bash')),'native_docker':native_docker}))
'@
    $probeResult = Invoke-WslPython $name $probe
    $result = $null
    if ($probeResult.ExitCode -eq 0) {
        try { $result = ($probeResult.Output | ConvertFrom-Json) } catch { $result = $null }
    }
    if (-not $result) {
        $probeResult = Invoke-WslPythonStdin $name $probe
        if ($probeResult.ExitCode -eq 0) {
            try { $result = ($probeResult.Output | ConvertFrom-Json) } catch { $result = $null }
        }
    }
    if ($result -and (-not $result.python -or $result.python.Count -lt 2)) { $result = $null }
    $version = if ($versions.ContainsKey($name)) { [int]$versions[$name] } else { 0 }
    $score = 0
    if ($version -eq 2 -and $result -and $result.bash -and
        ($result.python[0] -gt 3 -or ($result.python[0] -eq 3 -and $result.python[1] -ge 10))) {
        $score = 60
        if ($result.id -eq 'ubuntu') {
            $ubuntuVersion = $null
            if (-not [version]::TryParse([string]$result.version, [ref]$ubuntuVersion)) { $ubuntuVersion = [version]'0.0' }
            $score = if ($ubuntuVersion -ge [version]'24.04') { 100 } else { 90 }
        }
        elseif ($result.id -eq 'debian') { $score = 80 }
        if ($result.native_docker) { $score = 0 }
    }
    $reason = if ($version -eq 0) { 'WSL version could not be verified' }
        elseif ($version -ne 2) { 'WSL 2 required' }
        elseif (-not $result) { "Python probe failed (exit $($probeResult.ExitCode)); try Install.cmd as administrator under this same Windows account" }
        elseif (-not $result.bash) { 'bash unavailable' }
        elseif ($result.native_docker) { 'A native Docker Engine is running here. Use a separate WSL distro (choose N); existing containers will be left running.' }
        elseif ($score -eq 0) { 'Python 3.10+ required' }
        else { 'recommended' }
    return [pscustomobject]@{Name=$name;Version=$version;Score=$score;Reason=$reason;
        Home=if ($result) { [string]$result.home } else { '' };
        Linux=if ($result) { "$($result.id) $($result.version)".Trim() } else { '' }}
}

function Get-OnlineUbuntu {
    $listing = Invoke-WslNative @('--list', '--online')
    if ($listing.ExitCode -ne 0) { return 'Ubuntu' }
    $lines = @($listing.Output) | ForEach-Object { $_ -replace "`0", '' }
    if (($lines -join "`n") -match '(?m)^\s*Ubuntu-24\.04\s') { return 'Ubuntu-24.04' }
    return 'Ubuntu'
}

function Install-WslDistribution([string]$name) {
    Write-Host "Installing WSL distribution: $name"
    $wsl = Join-Path $env:WINDIR 'System32\wsl.exe'
    if ($Interactive) {
        Write-Host 'A Linux window may open for first-run account setup. After creating the account, type exit in that Linux window to continue this installer.'
        $process = Start-Process -FilePath $wsl -ArgumentList @('--install', '--distribution', $name) -Verb RunAs -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "WSL installation exited with code $($process.ExitCode). Restart Windows if prompted, then rerun Install.cmd."
        }
        Write-Host 'Complete the Linux first-run username setup if prompted.'
    } else {
        # --no-launch skips the first-run account prompt. Initialize-WslDistribution
        # creates the account instead. Elevation is only needed to enable WSL itself.
        $install = Invoke-DesktopNative 'wsl.exe' @('--install', '--distribution', $name, '--no-launch') 1800
        if ($install.ExitCode -ne 0) {
            Write-Host "Requesting administrator access to enable WSL: $($install.Output)"
            $process = Start-Process -FilePath $wsl -ArgumentList @('--install', '--distribution', $name, '--no-launch') `
                -Verb RunAs -Wait -PassThru
            if ($process.ExitCode -ne 0) {
                throw "WSL installation exited with code $($process.ExitCode). Restart Windows if prompted, then rerun Install.cmd."
            }
        }
    }
    $installed = @()
    try { $installed = @(Get-WslNames) } catch { }
    if ($name -notin $installed) {
        if (-not $Interactive) {
            # Enabling WSL for the first time takes effect after a restart.
            $command = $resumeCommand
            New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                -Name 'CTF Agent Install' -Value $command -PropertyType String -Force | Out-Null
            Write-Host 'Installation continues automatically after you restart Windows and sign in.'
        }
        Write-Host 'Restart Windows, finish WSL setup, and rerun Install.cmd.'
        exit 20
    }
}

function Initialize-WslDistribution([string]$name) {
    # Returns $true when Docker Desktop has to reconnect to this distribution.
    Write-Host "Preparing WSL distribution $name..."
    $converted = Invoke-DesktopNative 'wsl.exe' @('--distribution', $name, '--user', 'root',
        '--exec', 'wslpath', '-a', '-u', $wslPreparation) 120
    $linuxScript = $converted.Stdout.Trim()
    if ($converted.ExitCode -ne 0 -or -not $linuxScript.StartsWith('/')) {
        throw "$name cannot read the release folder: $($converted.Output)"
    }
    $current = Invoke-DesktopNative 'wsl.exe' @('--distribution', $name, '--exec', 'id', '-un') 60
    if ($current.ExitCode -ne 0) { throw "$name did not start: $($current.Output)" }
    $defaultUser = $current.Stdout.Trim()
    $prepared = Invoke-DesktopNative 'wsl.exe' @('--distribution', $name, '--user', 'root',
        '--exec', '/bin/sh', $linuxScript, $defaultUser) 900
    if ($prepared.ExitCode -ne 0 -or $prepared.Stdout -notmatch '(?m)^ready user=(\S+) changed=([01])\s*$') {
        throw "$name could not be prepared: $($prepared.Output)"
    }
    $serviceUser = $Matches[1]
    $changed = $Matches[2] -eq '1'
    if ($serviceUser -ne $defaultUser) {
        # /etc/wsl.conf is read when the distribution starts.
        Write-Host "CTF Agent cannot run as root. The default Linux user of $name is now $serviceUser; wsl --user root still works."
        Invoke-DesktopNative 'wsl.exe' @('--terminate', $name) 30 | Out-Null
    }
    $verified = Invoke-DesktopNative 'wsl.exe' @('--distribution', $name, '--exec', '/bin/sh', '-c',
        'test "$(id -u)" != 0 && mkdir -p "$HOME/.docker/run" && id -un') 60
    if ($verified.ExitCode -ne 0 -or $verified.Stdout.Trim() -ne $serviceUser) {
        throw "The Linux user of $name is not ready: $($verified.Output)"
    }
    return $changed
}

function Select-PreparedWslDistribution([object[]]$infos, [string]$preferredName) {
    # Candidates start one at a time so that distributions which are not needed
    # stay stopped. See the WSL#41084 note in Get-WslCandidateInfo.
    if ($Distribution) {
        if ($Distribution -notin @($infos | ForEach-Object { $_.Name })) { Install-WslDistribution $Distribution }
        return [pscustomobject]@{Name=$Distribution;Reconnect=(Initialize-WslDistribution $Distribution)}
    }
    $ordered = @($infos | Where-Object { $_.Score -gt 0 } |
        Sort-Object @{Expression={ $_.Name -eq $preferredName };Descending=$true},
            @{Expression='Score';Descending=$true})
    foreach ($candidate in $ordered) {
        try {
            $reconnect = Initialize-WslDistribution $candidate.Name
            $checked = Get-WslInfo $candidate.Name (Get-WslVersions)
            if ($checked.Score -gt 0) {
                return [pscustomobject]@{Name=$candidate.Name;Reconnect=$reconnect}
            }
            Write-Warning "Skipping $($candidate.Name): $($checked.Reason)"
        } catch { Write-Warning "Skipping $($candidate.Name): $($_.Exception.Message)" }
    }
    $new = Get-OnlineUbuntu
    Write-Host "No usable WSL distribution was found. Installing $new."
    Install-WslDistribution $new
    return [pscustomobject]@{Name=$new;Reconnect=(Initialize-WslDistribution $new)}
}

function Select-WslDistribution([object[]]$infos, [string]$savedName) {
    $ordered = @($infos | Sort-Object Score -Descending)
    if ($Distribution) {
        $requested = @($ordered | Where-Object { $_.Name -eq $Distribution } |
            Select-Object -First 1)
        if ($requested.Count) {
            if ($requested[0].Score -le 0) {
                throw "The selected WSL distribution is not usable: $($requested[0].Reason)"
            }
            return $requested[0].Name
        }
        if ($Distribution -notmatch '^Ubuntu(?:-[0-9]{2}\.[0-9]{2})?$') {
            throw "Distribution $Distribution is not installed. Choose an installed WSL distribution or a supported Ubuntu release."
        }
        Install-WslDistribution $Distribution
        return $Distribution
    }
    if ($ordered.Count) {
        Write-Host 'Available WSL distributions:'
        for ($index = 0; $index -lt $ordered.Count; $index++) {
            $info = $ordered[$index]
            $label = if ($info.Score -le 0) { $info.Reason }
                elseif ($info.ProbeDeferred) { 'checked after selection' } else { 'usable' }
            Write-Host "  $($index + 1). $($info.Name) ($($info.Linux), WSL $($info.Version)) - $label"
        }
    }
    $ready = @($ordered | Where-Object { $_.Score -gt 0 })
    if (-not $ready.Count) {
        $account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        if ($ordered.Count) {
            Write-Warning "Installed WSL distributions are visible for $account, but none passed the checks above."
            Write-Host '  1. Install a new Ubuntu distribution (default)'
            Write-Host '  2. Stop and repair an existing distribution'
            if ((Read-TimedChoice 'Choose WSL setup' '1' @('1','2')) -ne '1') {
                throw 'No WSL distribution passed the checks. Repair an existing one and rerun Install.cmd.'
            }
            $candidate = Get-OnlineUbuntu
            if ($candidate -in @($ordered | ForEach-Object Name)) {
                $candidate = if ($candidate -eq 'Ubuntu-24.04') { 'Ubuntu' } else { 'Ubuntu-24.04' }
            }
            if ($candidate -in @($ordered | ForEach-Object Name)) {
                throw 'Both standard Ubuntu distribution names already exist. Repair one or select a usable distribution with -Distribution.'
            }
            Install-WslDistribution $candidate
            return $candidate
        }
        Write-Host "No WSL distributions are visible for Windows account: $account"
        Write-Host 'If they belong to a different Windows account, run Install.cmd while signed in as that account.'
        $candidate = Get-OnlineUbuntu
        Write-Host "  1. Install $candidate (default)"
        Write-Host '  2. Stop without installing WSL'
        if ((Read-TimedChoice 'Choose WSL setup' '1' @('1','2')) -ne '1') {
            throw 'A WSL 2 distribution with bash and Python 3.10+ is required.'
        }
        Install-WslDistribution $candidate
        return $candidate
    }
    $default = 1
    if ($savedName) {
        for ($index = 0; $index -lt $ordered.Count; $index++) {
            if ($ordered[$index].Name -eq $savedName -and $ordered[$index].Score -gt 0) {
                $default = $index + 1
                break
            }
        }
    }
    $newUbuntu = Get-OnlineUbuntu
    if ($newUbuntu -in @($ordered | ForEach-Object Name)) {
        $newUbuntu = if ($newUbuntu -eq 'Ubuntu-24.04') { 'Ubuntu' } else { 'Ubuntu-24.04' }
    }
    if ($newUbuntu -notin @($ordered | ForEach-Object Name)) {
        Write-Host "  N. Install $newUbuntu as a new distribution"
    }
    while ($true) {
        $choices = @(1..$ordered.Count | ForEach-Object { [string]$_ })
        if ($newUbuntu -notin @($ordered | ForEach-Object Name)) { $choices += @('n', 'N') }
        $answer = Read-TimedChoice 'Choose distribution, or N for a new Ubuntu' ([string]$default) $choices
        if ($answer -in @('n', 'N')) {
            Install-WslDistribution $newUbuntu
            return $newUbuntu
        }
        $number = 0
        if ([int]::TryParse($answer, [ref]$number) -and $number -ge 1 -and $number -le $ordered.Count) {
            $selected = $ordered[$number - 1]
            if ($selected.Score -gt 0) { return $selected.Name }
            Write-Host "This distribution is not suitable: $($selected.Reason)"
        } else { Write-Host 'Choose one of the displayed numbers.' }
    }
}

function Assert-StorageCapacity([string]$distro, [string]$linuxHome,
    [int64]$estimatedWriteBytes = 0) {
    $diskProbe = @'
import json,os,shutil,sys
p=sys.argv[1]
while not os.path.exists(p):
    parent=os.path.dirname(p)
    if parent==p: raise SystemExit(2)
    p=parent
print(json.dumps({'free':shutil.disk_usage(p).free,'existing':p}))
'@
    $probeResult = Invoke-WslPython $distro $diskProbe @($linuxHome)
    if ($probeResult.ExitCode -ne 0) { throw 'Could not check free space inside the selected WSL distribution.' }
    $wslFree = [int64](($probeResult.Output | ConvertFrom-Json).free)
    $hostFree = Get-HostVolumeFree (Get-WslDiskHostPath $distro)
    Write-Host ('WSL free: {0:N1} GB; Windows backing volume free: {1:N1} GB' -f ($wslFree / 1GB), ($hostFree / 1GB))
    $required = $minimumFreeBytes + $estimatedWriteBytes
    if ($wslFree -lt $required -or $hostFree -lt $required) {
        throw ('At least {0:g} GiB free is required inside WSL and on its Windows backing volume to leave 5 GiB after estimated installation writes.' -f ($required / 1GB))
    }
    if ((Get-HostVolumeFree $env:SystemDrive) -lt $minimumFreeBytes) {
        Write-Warning 'The Windows system drive has less than 5 GiB free. Docker Desktop may need more space there.'
    }
}

function Get-DockerDesktopExecutable {
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Ensure-DockerDesktop([string]$distro, [bool]$reconnect = $false) {
    $desktop = Get-DockerDesktopExecutable
    $choice = if ($script:SelectedDockerMode) { $script:SelectedDockerMode } else { $DockerMode }
    if (-not $choice) {
        if ($desktop) {
            Write-Host 'Docker Desktop is already installed:'
            Write-Host '  1. Use the existing installation (default)'
            Write-Host '  2. Install or update Docker Desktop'
        } else {
            Write-Host 'Docker Desktop is not installed:'
            Write-Host '  1. Install it now (default)'
            Write-Host '  2. Stop without installing Docker Desktop'
        }
        $answer = Read-TimedChoice 'Choose Docker Desktop setup' '1' @('1','2')
        if ($desktop) { $choice = if ($answer -eq '1') { 'Existing' } else { 'Install' } }
        elseif ($answer -eq '1') { $choice = 'Install' }
        else { throw 'Docker Desktop is required. The installation stopped before changing Docker.' }
    }
    if ($choice -eq 'Existing' -and -not $desktop) {
        throw 'DockerMode Existing was requested, but Docker Desktop is not installed.'
    }
    if ($choice -eq 'Install') {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            Start-Process 'https://docs.docker.com/desktop/setup/install/windows-install/'
            throw 'winget is unavailable. Install Docker Desktop from the opened official page and rerun Install.cmd.'
        }
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $wingetAction = if ($desktop) { 'upgrade' } else { 'install' }
            & winget.exe $wingetAction --id Docker.DockerDesktop --exact --source winget `
                --accept-source-agreements --accept-package-agreements
            $wingetExit = $LASTEXITCODE
        } finally { $ErrorActionPreference = $previousPreference }
        if ($wingetExit -ne 0) { throw "Docker Desktop installation or update failed (exit code $wingetExit)." }
        $desktop = Get-DockerDesktopExecutable
        if (-not $desktop) { throw 'Finish Docker Desktop installation and rerun Install.cmd.' }
    }
    Ensure-DockerWslIntegration $distro @(Get-WslNames) $desktop $reconnect
    Write-Host "Checking Docker Desktop in WSL distribution $distro..."
    $waitSeconds = if ($choice -eq 'Install') { 900 } else { 240 }
    Wait-WslDockerReady $distro $waitSeconds -AllowRepair
    $script:SelectedDockerMode = 'Existing'
}

function Ensure-DockerDiskCapacity([string]$distro, [int64]$imageWorkBytes) {
    # Running out of room on this drive can freeze the whole WSL VM mid-install,
    # so the disk moves first when another drive can hold it.
    $disk = Resolve-DockerDesktopDiskFile
    $required = [int64]5GB + $imageWorkBytes
    $folder = $DockerFolder
    if ($folder) {
        if ((Split-Path -Parent (Split-Path -Parent $disk)) -ieq $folder.TrimEnd('\', '/')) { return }
    } else {
        if ((Get-HostVolumeFree $disk) -ge $required) { return }
        $folder = Select-DockerDiskFolder $disk $required $requestedDatabaseVhd
        if (-not $folder) { return }
    }
    if ($DockerFolder -or (Ask-YesNo "Move Docker Desktop's disk to ${folder}?" (-not $Interactive))) {
        Move-DockerDesktopDisk $folder
        Ensure-DockerDesktop $distro
    }
}

function Get-LinuxDataFolderProblem([string]$path) {
    if ($path.StartsWith('\\')) { return 'Enter a WSL Linux path or a local Windows drive path.' }
    if (-not $path.StartsWith('/') -or $path -match '[\x00-\x1f]' -or
        $path -match '(^|/)\.\.(/|$)' -or $path -match '^/mnt/[A-Za-z](/|$)') {
        return 'Enter an absolute WSL Linux path outside /mnt/<Windows drive>.'
    }
    return ''
}

# Keep caller-supplied choices when Windows needs a restart to enable WSL.
# Encoding the command avoids losing array arguments or interpreting a path as
# command syntax in the RunOnce registry value.
$resumeOptions = @{}
foreach ($pair in $PSBoundParameters.GetEnumerator()) {
    $resumeOptions[$pair.Key] = if ($pair.Value -is [System.Management.Automation.SwitchParameter]) {
        [bool]$pair.Value
    } else { $pair.Value }
}
$resumeData = @{script=(Join-Path $PSScriptRoot 'Install.ps1');options=$resumeOptions} |
    ConvertTo-Json -Compress -Depth 5
$resumeData64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($resumeData))
$resumeCode = @'
$data = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('PAYLOAD')) | ConvertFrom-Json
$arguments = @{}
foreach ($item in $data.options.PSObject.Properties) { $arguments[$item.Name] = $item.Value }
& ([string]$data.script) @arguments
'@.Replace('PAYLOAD', $resumeData64)
$resumeCommand = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' +
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($resumeCode))
Write-Host 'CTF Agent local installer'
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'This Windows version does not provide wsl.exe. Update Windows and rerun Install.cmd.'
}
$saved = $null
if (Test-Path -LiteralPath $stateFile -PathType Leaf) {
    try { $saved = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $saved = $null }
}
$versions = @{}
$names = @()
try {
    $versions = Get-WslVersions
    $names = @(Get-WslNames)
} catch {
    # Listing fails until WSL is enabled and has a distribution to list.
    if ($Interactive) { throw }
    Write-Host "No WSL distribution is available yet: $($_.Exception.Message)"
}
if (-not $names.Count) {
    $names = @($versions.Keys | Where-Object { $_ -notlike 'docker-desktop*' })
    if ($names.Count) { Write-Warning 'WSL quiet listing was empty; checking the registered distribution names.' }
}
$infos = @($names | ForEach-Object { Get-WslCandidateInfo $_ $versions })
$preferredDistro = [string]$saved.distro
if (-not $preferredDistro) {
    $registrationRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    $defaultId = (Get-ItemProperty -LiteralPath $registrationRoot -ErrorAction SilentlyContinue).DefaultDistribution
    if ($defaultId) {
        $preferredDistro = [string](Get-ItemProperty -LiteralPath (Join-Path $registrationRoot $defaultId) -ErrorAction SilentlyContinue).DistributionName
    }
}
if (-not $Interactive -and $saved.distro -and [string]$saved.distro -notin $names) {
    Write-Warning "$($saved.distro) from the previous installation no longer exists. Starting a new installation."
    if (-not $DatabaseFolder) { $DatabaseFolder = [string]$saved.db_vhd }
    $saved = $null
    $preferredDistro = ''
    $orphanedInstall = $true
}
$distro = Select-WslDistribution $infos $preferredDistro
$dockerReconnect = Initialize-WslDistribution $distro
Write-Host "Using WSL distribution: $distro"
if (-not $versions.ContainsKey($distro)) { $versions = Get-WslVersions }
$selectedInfo = Get-WslInfo $distro $versions
if ($selectedInfo.Score -le 0) {
    Write-Warning "Selected distribution is not ready: $($selectedInfo.Reason)"
    if ($Distribution) { throw "The requested WSL distribution $distro is not ready." }
    foreach ($alternative in @($infos | Where-Object { $_.Name -ne $distro -and $_.Score -gt 0 } |
            Sort-Object Score -Descending)) {
        try {
            $reconnect = Initialize-WslDistribution $alternative.Name
            $checked = Get-WslInfo $alternative.Name (Get-WslVersions)
            if ($checked.Score -gt 0) {
                $distro = $alternative.Name
                $dockerReconnect = $reconnect
                $selectedInfo = $checked
                Write-Host "Using WSL distribution: $distro"
                break
            }
            Write-Warning "Skipping $($alternative.Name): $($checked.Reason)"
        } catch { Write-Warning "Skipping $($alternative.Name): $($_.Exception.Message)" }
    }
    if ($selectedInfo.Score -le 0) {
        throw 'No selected WSL distribution became ready. Repair WSL or rerun Install.cmd with -Distribution.'
    }
}
$defaultHome = "$($selectedInfo.Home.TrimEnd('/'))/.local/share/ctf-agent"
if ($saved -and $saved.distro -eq $distro -and $saved.home) { $defaultHome = [string]$saved.home }
Write-Host "Recommended data folder: $defaultHome"
Write-Host "Windows Explorer: \\wsl.localhost\$distro\$($defaultHome.TrimStart('/') -replace '/', '\')"
$requestedDatabaseVhd = ''
while ($Interactive -and -not $DataFolder -and -not $DatabaseFolder) {
    $answer = (Read-Host 'WSL data folder, or Windows folder for DB only [Enter for WSL default]').Trim()
    if ($answer -match '^"[A-Za-z]:[\\/].*"$' -or $answer -match '^[A-Za-z]:[\\/]') {
        $requestedDatabaseVhd = Resolve-DatabaseVhdInputPath $answer
        $linuxHome = $defaultHome
        Write-Host "Application files stay in WSL: $linuxHome"
        Write-Host "Database disk on Windows: $requestedDatabaseVhd"
        break
    }
    $linuxHome = if ($answer) { $answer } else { $defaultHome }
    $problem = Get-LinuxDataFolderProblem $linuxHome
    if (-not $problem) { break }
    Write-Host $problem
}
if (-not $Interactive -or $DataFolder -or $DatabaseFolder) {
    $linuxHome = if ($DataFolder) { $DataFolder } else { $defaultHome }
    $problem = Get-LinuxDataFolderProblem $linuxHome
    if ($problem) { throw $problem }
    if ($DatabaseFolder) {
        $requestedDatabaseVhd = Resolve-DatabaseVhdInputPath $DatabaseFolder
        Write-Host "Database disk on Windows: $requestedDatabaseVhd"
    }
}
if ($saved -and ($saved.distro -ne $distro -or $saved.home -ne $linuxHome) -and
    -not (Ask-YesNo 'This changes the data location. Existing data will not move automatically. Continue?' $false)) {
    throw 'Installation cancelled; existing data was not changed.'
}
if ($saved.db_vhd -and ($saved.distro -ne $distro -or $saved.home -ne $linuxHome)) {
    throw 'A separate database VHDX is bound to the original WSL distribution and installation path.'
}
# Unattended runs check after Docker Desktop's disk has moved off a full drive.
if ($Interactive) { Assert-StorageCapacity $distro $linuxHome }
$separateDatabase = if ($requestedDatabaseVhd) { $true } else {
    Ask-YesNo 'Store only the database on a separate ext4 VHDX on a Windows drive?' ([bool]$saved.db_vhd)
}
if (-not $separateDatabase -and $saved.db_vhd) {
    throw 'The existing separate database cannot be moved automatically. Keep its VHDX setting.'
}
$dbVhd = ''
$databaseMount = ''
$databasePath = ''
$dockerDatabasePath = ''
$dbUuid = ''
$validatedPreexistingTask = $false
if ($separateDatabase) {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        throw 'Windows Task Scheduler inspection is required for a separate database disk.'
    }
    if (-not $saved.db_task_managed -and
        (Get-ScheduledTask -TaskName (Get-DatabaseTaskName) -ErrorAction SilentlyContinue)) {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if (-not $saved.db_vhd -or -not (Test-DatabaseMountTask ([string]$saved.db_vhd) $sid)) {
            throw 'A scheduled task already uses the CTF Agent database name; it was not changed.'
        }
        $validatedPreexistingTask = $true
    }
    if ($linuxHome -match '^/mnt/wsl(/|$)') {
        throw 'For a separate database disk, keep the application data inside the selected WSL distribution.'
    }
    if (-not $saved.db_vhd) { Assert-FreshDatabaseHome $distro $linuxHome }
    $dbVhd = Select-DatabaseVhd ([string]$saved.db_vhd) $requestedDatabaseVhd
    if ((Get-HostVolumeFree $dbVhd) -lt $minimumFreeBytes) {
        throw 'The database drive needs at least 5 GiB free before installation.'
    }
    $databaseMount = Get-DatabaseMountPath
    $databasePath = "$databaseMount/Database/CTF_Agent"
    if ($saved.db_vhd) {
        if ([string]$saved.db_uuid -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
            throw 'The existing database disk identity is missing from installation settings.'
        }
        $dbUuid = [string]$saved.db_uuid
    }
}
$autoStartDefault = if ($saved -and $null -ne $saved.autoStart) { [bool]$saved.autoStart }
    elseif ($separateDatabase) { $false } else { $true }
$autoStart = if ($PSBoundParameters.ContainsKey('StartAtSignIn')) { [bool]$StartAtSignIn }
    else { Ask-YesNo 'Start CTF Agent automatically when you sign in to Windows?' $autoStartDefault }
$loginDefault = -not ($NoLogin -or ($saved -and $saved.authMode -eq 'nologin'))
$requireLogin = if ($PSBoundParameters.ContainsKey('NoLogin')) { -not [bool]$NoLogin }
    else { Ask-YesNo 'Require account login on this computer?' $loginDefault }
$authMode = if ($requireLogin) { 'password' } else { 'nologin' }
$urlInput = if ($PSBoundParameters.ContainsKey('PublicUrl')) { $PublicUrl }
    elseif ($saved -and $saved.public_urls) { @($saved.public_urls) } else { @() }
$publicUrls = @(Get-InstallPublicUrls $urlInput)
$previousListen = ''
if ($saved -and -not [string]$saved.listen_address -and -not $ListenAddress -and
    -not $PSBoundParameters.ContainsKey('PublicUrl')) {
    # Early installers kept the bind choice only in the Linux configuration.
    # Preserve it during upgrade, even though the Windows state lacks the key.
    $readListen = @'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])/'.local-config.json'
if p.is_file() and not p.is_symlink():
    print(json.loads(p.read_text(encoding='utf-8')).get('listen_address',''))
'@
    $prior = Invoke-WslPython $distro $readListen @($linuxHome) -ReadOnly
    if ($prior.ExitCode -eq 0 -and $prior.Output.Trim() -in @('127.0.0.1','0.0.0.0')) {
        $previousListen = $prior.Output.Trim()
    }
}
if (-not $ListenAddress) {
    $ListenAddress = if ($PSBoundParameters.ContainsKey('PublicUrl') -and $publicUrls.Count) {
        '0.0.0.0'
    } elseif ($saved -and [string]$saved.listen_address) {
        [string]$saved.listen_address
    } elseif ($previousListen) { $previousListen
    } elseif ($publicUrls.Count) { '0.0.0.0' } else { '127.0.0.1' }
}
if ($ListenAddress -notin @('127.0.0.1', '0.0.0.0')) {
    throw 'ListenAddress must be 127.0.0.1 or 0.0.0.0.'
}
$accessMode = if ($PSBoundParameters.ContainsKey('OpenAccess')) {
    if ($OpenAccess) { 'open' } else { 'link' }
} elseif ($saved -and [string]$saved.access_mode -eq 'open') { 'open' } else { 'link' }
if ($accessMode -eq 'open' -and $authMode -ne 'nologin') {
    throw 'OpenAccess requires NoLogin. Use -NoLogin -OpenAccess together.'
}
if ($accessMode -eq 'open') {
    Write-Warning 'OpenAccess lets anyone who reaches the configured address use this installation without an account.'
}
Ensure-DockerDesktop $distro $dockerReconnect
if ($orphanedInstall) {
    Remove-OrphanedCtfAgentContainers
    Ensure-DockerDesktop $distro
}
# The second pass budgets application staging, Docker image work and optional
# database VHDX growth on their actual Windows drives. The initial check only
# establishes that the selected WSL location is feasible.
$revisionFile = Join-Path $PSScriptRoot 'COMMIT'
$releaseRevision = if (Test-Path -LiteralPath $revisionFile -PathType Leaf) {
    (Get-Content -LiteralPath $revisionFile -Raw).Trim()
} else { '' }
$imageWorkBytes = Get-EstimatedImageWorkBytes $releaseRevision
$applicationWorkBytes = [int64]1GB
Ensure-DockerDiskCapacity $distro $imageWorkBytes
Assert-StorageCapacity $distro $linuxHome $applicationWorkBytes
Assert-DockerDesktopImageCapacity $imageWorkBytes
$dockerImageDisk = Resolve-DockerDesktopDiskFile
Assert-LocalInstallVolumeCapacity -WslDiskPath (Get-WslDiskHostPath $distro) `
    -DockerDiskPath $dockerImageDisk -DatabaseDiskPath $dbVhd `
    -ApplicationWorkBytes $applicationWorkBytes -ImageWorkBytes $imageWorkBytes | Out-Null
if ($separateDatabase) {
    $dbUuid = Initialize-DatabaseVhd $distro $dbVhd $dbUuid
    Write-Host "Database filesystem: $dbVhd -> $databasePath"
    # A verified filesystem can be reused after an interrupted installation.
    # Save its identity before release download or Docker startup can fail.
    $pendingDir = Split-Path -Parent $stateFile
    New-Item -ItemType Directory -Path $pendingDir -Force | Out-Null
    $dbTaskManaged = ([bool]$saved.db_task_managed -or $validatedPreexistingTask)
    @{distro=$distro;home=$linuxHome;autoStart=$dbTaskManaged;authMode=$authMode;
        listen_address=$ListenAddress;public_urls=$publicUrls;access_mode=$accessMode;
        db_vhd=$dbVhd;database_mount=$databaseMount;database_path=$databasePath;
        db_uuid=$dbUuid;db_task_managed=$dbTaskManaged;pending_install=$true} |
        ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
    # This account owns the VHDX, so Start.cmd can attach it without elevation
    # at sign-in. Only the logon task from an older release needs removing.
    if ($dbTaskManaged) {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Invoke-ElevatedDatabaseAction 'unregister-task' $dbVhd $sid
        $dbTaskManaged = $false
    }
    @{distro=$distro;home=$linuxHome;autoStart=$autoStart;authMode=$authMode;
        listen_address=$ListenAddress;public_urls=$publicUrls;access_mode=$accessMode;
        db_vhd=$dbVhd;database_mount=$databaseMount;database_path=$databasePath;
        db_uuid=$dbUuid;db_task_managed=$dbTaskManaged;pending_install=$true} |
        ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
}
# A v0.4.22 root-run overlay build could have left the previous release's
# metadata unreadable to this distribution's normal user. The Linux installer
# verifies that previous image before it stages the replacement release.
Repair-LocalRuntimeMetadata $distro $linuxHome
# Installation already waited for Docker Desktop before attaching the VHD.
# Verify its identity again after the intervening WSL probes, immediately
# before the Linux installer can start containers.
if ($dbVhd) {
    Ensure-DatabaseMount $distro $dbVhd $dbUuid $dbTaskManaged
    $dockerDatabasePath = Ensure-DatabaseBindLink $distro $linuxHome $databasePath `
        -AllowCreateDatabaseDirectory:([bool]$saved.pending_install -or -not [bool]$saved.db_vhd)
}
$pathResult = Invoke-WslNative @('--distribution', $distro, '--exec', 'wslpath', '-a', '-u', $installer)
$linuxPath = @($pathResult.Output)
if ($pathResult.ExitCode -ne 0 -or -not $linuxPath.Count -or -not $linuxPath[0].StartsWith('/')) {
    throw 'The selected WSL distribution cannot access the extracted release folder.'
}
if ($dbVhd) {
    Ensure-DatabaseMount $distro $dbVhd $dbUuid $dbTaskManaged
    $dockerDatabasePath = Ensure-DatabaseBindLink $distro $linuxHome $databasePath `
        -AllowCreateDatabaseDirectory:([bool]$saved.pending_install -or -not [bool]$saved.db_vhd)
}
$installResult = Invoke-WslNative @('--distribution', $distro, '--exec', 'env',
    "CTF_LOCAL_HOME=$linuxHome", "CTF_LOCAL_AUTOSTART=$($autoStart.ToString().ToLowerInvariant())",
    "CTF_LOCAL_AUTH_MODE=$authMode", "CTF_LOCAL_DATABASE=$dockerDatabasePath",
    "CTF_LOCAL_FS_DATABASE=$databasePath", "CTF_LOCAL_DB_MOUNT=$databaseMount",
    "CTF_LOCAL_BIND=$ListenAddress",
    "CTF_LOCAL_PUBLIC_URLS=$($publicUrls -join ',')", "CTF_LOCAL_ACCESS=$accessMode",
    'bash', $linuxPath[0]) -Visible
if ($installResult.ExitCode -ne 0) { throw "Local installation failed (exit code $($installResult.ExitCode))." }
$stateDir = Split-Path -Parent $stateFile
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
foreach ($name in @('Start.cmd', 'Start.ps1', 'Uninstall.cmd', 'Uninstall.ps1', 'RemoteLink.cmd', 'RemoteLink.ps1',
        'DatabaseDisk.ps1', 'DockerDesktop.ps1', 'DockerDisk.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stateDir $name) -Force
}
$state = @{distro=$distro;home=$linuxHome;autoStart=$autoStart;
    authMode=$authMode;listen_address=$ListenAddress;public_urls=$publicUrls;access_mode=$accessMode;
    db_vhd=$dbVhd;database_mount=$databaseMount;database_path=$databasePath;
    db_uuid=$dbUuid;db_task_managed=if ($dbVhd) { $dbTaskManaged } else { $false };pending_install=$false}
$state | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'CTF Agent Local.lnk'
$targetPath = Join-Path $stateDir 'Start.cmd'
$shell = New-Object -ComObject WScript.Shell
if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
    $existing = $shell.CreateShortcut($shortcutPath)
    if ($existing.TargetPath -ne $targetPath) { throw 'A different startup shortcut uses the CTF Agent name.' }
    if (-not $autoStart) { Remove-Item -LiteralPath $shortcutPath }
}
if ($autoStart) {
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $targetPath
    $shortcut.WorkingDirectory = $stateDir
    $shortcut.WindowStyle = 7
    $shortcut.Save()
}
Wait-CtfAgentReady $distro $linuxHome
$listenAddress = Get-CtfAgentListenAddress $distro $linuxHome
if ($listenAddress -eq '0.0.0.0') { Ensure-CtfAgentFirewallRule }
if ($requireLogin -or $accessMode -eq 'open') { Start-Process -FilePath 'http://127.0.0.1:5050' }
else { Open-CtfAgentLocalBrowser $distro $linuxHome }
Write-Host ''
Write-Host 'CTF Agent is ready: http://127.0.0.1:5050'
if ($listenAddress -eq '0.0.0.0') {
    Write-Host "Port 5050 accepts connections from this computer's network interfaces."
    if (-not $publicUrls.Count) { Write-Host 'For access outside your network, configure your own router or tunnel.' }
    if (-not $requireLogin -and $accessMode -eq 'link') {
        Write-Host "Other devices need a one-time link: $(Join-Path $stateDir 'RemoteLink.cmd') <public address>"
    }
}
if ($publicUrls.Count) { Write-Host "Public address: $($publicUrls -join ', ')" }
if ($requireLogin -and ($listenAddress -eq '0.0.0.0' -or $publicUrls.Count)) {
    $tokenProbe = @'
import json,pathlib,re,sys
p=pathlib.Path(sys.argv[1])/'.local-config.json'
if p.is_symlink() or not p.is_file(): raise SystemExit(2)
value=json.loads(p.read_text(encoding='utf-8'))
token=value.get('first_admin_setup_token','')
if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,}',token): raise SystemExit(2)
print(token)
'@
    $tokenResult = Invoke-WslPython $distro $tokenProbe @($linuxHome)
    if ($tokenResult.ExitCode -ne 0) { throw 'The first-administrator setup token is missing from the installed configuration.' }
    Write-Host "First administrator setup token: $($tokenResult.Output.Trim())"
    Write-Host 'Use this token only when creating the first administrator account.'
}
Write-Host ''
Write-Host "Start: $(Join-Path $stateDir 'Start.cmd')"
Write-Host "Uninstall: $(Join-Path $stateDir 'Uninstall.cmd')"
if ($requireLogin) { Write-Host 'The local site was opened in your browser. Create the first administrator account there.' }
else { Write-Host 'The local site was opened in your browser. Run Start.cmd to connect another browser later.' }
Write-Host "Files in Explorer: \\wsl.localhost\$distro\$($linuxHome.TrimStart('/') -replace '/', '\')\ctf_agent_data\workspace_files"
if ($dbVhd) {
    Write-Host "Database VHDX on Windows: $dbVhd"
    Write-Host "Database in Explorer: \\wsl.localhost\$distro\mnt\wsl\ctf-agent-db\Database\CTF_Agent"
}
