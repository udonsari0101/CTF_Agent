# Shared by Install, Start and Uninstall. No app or WSL configuration is changed
# when this file is loaded.
function ConvertTo-DesktopArgument([string]$value) {
    # ProcessStartInfo.ArgumentList is unavailable in Windows PowerShell 5.1.
    # WSL parses its switches itself; unnecessary quotes around --distribution
    # can cause the whole invocation to be interpreted as a Linux command.
    if ($value.Length -gt 0 -and $value -notmatch '[\s"]') { return $value }
    $escaped = [regex]::Replace($value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function ConvertFrom-DesktopBytes([byte[]]$bytes) {
    if (-not $bytes.Length) { return '' }
    $encoding = [Text.Encoding]::UTF8
    $sample = [Math]::Min(80, $bytes.Length)
    $oddNull = 0
    for ($index = 1; $index -lt $sample; $index += 2) {
        if ($bytes[$index] -eq 0) { $oddNull++ }
    }
    if (($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) -or
        $oddNull -ge 2) { $encoding = [Text.Encoding]::Unicode }
    return $encoding.GetString($bytes).TrimStart([char]0xfeff).Trim()
}

function Invoke-DesktopNative([string]$file, [string[]]$arguments,
    [int]$timeoutSeconds = 15) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $file
    $start.Arguments = (@($arguments | ForEach-Object { ConvertTo-DesktopArgument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $stdout = New-Object IO.MemoryStream
    $stderr = New-Object IO.MemoryStream
    $process = $null
    try {
        $process = [Diagnostics.Process]::Start($start)
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        $timedOut = -not $process.WaitForExit($timeoutSeconds * 1000)
        if ($timedOut) {
            $process.Kill()
            $process.WaitForExit()
        }
        $drained = [Threading.Tasks.Task]::WaitAll(
            [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 3000)
        if (-not $drained) { throw 'Timed out reading command output.' }
        $outText = ConvertFrom-DesktopBytes $stdout.ToArray()
        $errText = ConvertFrom-DesktopBytes $stderr.ToArray()
        $parts = @($outText, $errText) | Where-Object { $_ }
        $detail = $parts -join "`n"
        if ($timedOut) { $detail = "Command timed out after $timeoutSeconds seconds. $detail" }
        return [pscustomobject]@{ExitCode=if ($timedOut) { -1 } else { $process.ExitCode };
            Output=$detail;Stdout=$outText;Stderr=$errText;TimedOut=$timedOut}
    } catch {
        return [pscustomobject]@{ExitCode=-1;Output=$_.Exception.Message;Stdout='';Stderr=$_.Exception.Message;TimedOut=$false}
    } finally {
        if ($process) { $process.Dispose() }
        $stdout.Dispose()
        $stderr.Dispose()
    }
}

function Repair-LocalRuntimeMetadata([string]$distro, [string]$linuxHome) {
    # A previous root-run local overlay build could leave this non-secret
    # identity file root-owned and mode 0600. Repair only that exact file in
    # the installed release, and only when the normal WSL user cannot read it.
    $probe = @'
import os,pathlib,re,stat,sys
home=pathlib.Path(sys.argv[1])
if not home.is_absolute() or str(home)=="/" or os.path.realpath(home)!=os.path.normpath(home):
    raise SystemExit("Invalid installation path")
marker=home/".current-release"
if not marker.exists() and not marker.is_symlink():
    print("absent")
    raise SystemExit(0)
if marker.is_symlink() or not marker.is_file():
    raise SystemExit("Invalid installed release marker")
version=marker.read_text(encoding="ascii").strip()
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?",version):
    raise SystemExit("Invalid installed release version")
release=home/"releases"/version
if release.is_symlink() or not release.is_dir() or os.path.realpath(release)!=str(release):
    raise SystemExit("Invalid installed release directory")
target=release/".local-runtime.json"
if not target.exists() and not target.is_symlink():
    print("absent")
    raise SystemExit(0)
mode=target.lstat().st_mode
if not stat.S_ISREG(mode):
    raise SystemExit("Invalid local runtime identity file")
try:
    with target.open("rb") as stream:
        stream.read(1)
except PermissionError:
    print("repair:%s:%s"%(os.getuid(),os.getgid()))
else:
    print("readable")
'@
    $repair = @'
import json,os,pathlib,re,stat,sys
home=pathlib.Path(sys.argv[1])
uid,gid=map(int,sys.argv[2:4])
if uid<=0 or gid<0 or not home.is_absolute() or str(home)=="/" or os.path.realpath(home)!=os.path.normpath(home):
    raise SystemExit("Invalid local runtime repair request")
marker=home/".current-release"
if marker.is_symlink() or not marker.is_file():
    raise SystemExit("Invalid installed release marker")
version=marker.read_text(encoding="ascii").strip()
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?",version):
    raise SystemExit("Invalid installed release version")
release=home/"releases"/version
if release.is_symlink() or not release.is_dir() or os.path.realpath(release)!=str(release):
    raise SystemExit("Invalid installed release directory")
target=release/".local-runtime.json"
fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_size>16384:
        raise SystemExit("Local runtime metadata is not the known root-owned file")
    with os.fdopen(os.dup(fd),"r",encoding="utf-8") as stream:
        value=json.load(stream)
    if not isinstance(value,dict) or not all(key in value for key in
            ("base_ref","base_id","runtime_id","fingerprint","files")):
        raise SystemExit("Invalid local runtime identity")
    os.fchown(fd,uid,gid)
    os.fchmod(fd,0o600)
finally:
    os.close(fd)
'@
    $wrapper = 'import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))'
    $probe64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe))
    $result = Invoke-DesktopNative 'wsl.exe' @('--distribution',$distro,'--exec',
        'python3','-c',$wrapper,$probe64,$linuxHome) 15
    if ($result.ExitCode -ne 0) {
        throw "Could not inspect the installed local runtime metadata: $($result.Output)"
    }
    $status = $result.Stdout.Trim()
    if ($status -in @('absent','readable')) { return }
    if ($status -notmatch '^repair:([1-9][0-9]*):([0-9]+)$') {
        throw 'The installed local runtime metadata has an unexpected state.'
    }
    $uid = $Matches[1]
    $gid = $Matches[2]
    $repair64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($repair))
    $fixed = Invoke-DesktopNative 'wsl.exe' @('--distribution',$distro,'--user','root',
        '--exec','python3','-c',$wrapper,$repair64,$linuxHome,$uid,$gid) 15
    if ($fixed.ExitCode -ne 0) {
        throw "Could not repair the previous root-owned local runtime metadata: $($fixed.Output)"
    }
    $verify = Invoke-DesktopNative 'wsl.exe' @('--distribution',$distro,'--exec',
        'python3','-c',$wrapper,$probe64,$linuxHome) 15
    if ($verify.ExitCode -ne 0 -or $verify.Stdout.Trim() -ne 'readable') {
        throw 'The previous local runtime metadata is still unreadable after repair.'
    }
}

function Get-DesktopDockerCli {
    $command = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw 'Docker Desktop CLI is missing. Finish installing Docker Desktop first.'
}

function Get-WslDockerState([string]$distro) {
    $linux = Invoke-DesktopNative 'wsl.exe' @('--distribution', $distro,
        '--exec', 'docker', 'info', '--format={{.ID}}') 12
    $docker = Get-DesktopDockerCli
    # Always inspect the local Desktop engine, never a user's remote context.
    $windows = Invoke-DesktopNative $docker @('--context', 'desktop-linux',
        'info', '--format={{.ID}}') 8
    $linuxId = $linux.Stdout.Trim()
    $windowsId = $windows.Stdout.Trim()
    $validId = '^[A-Za-z0-9][A-Za-z0-9:-]{7,127}$'
    $bothReady = $linux.ExitCode -eq 0 -and $windows.ExitCode -eq 0 -and
        $linuxId -match $validId -and $windowsId -match $validId
    if ($bothReady -and $linuxId -eq $windowsId) {
        return [pscustomobject]@{Ready=$true;EngineReady=$true;SharedToolsMissing=$false;
            EngineMismatch=$false;Detail=$linux.Output;WindowsDetail=$windows.Output}
    }
    $missing = Invoke-DesktopNative 'wsl.exe' @('--distribution', $distro, '--exec',
        '/bin/sh', '-c', 'test -L /usr/bin/docker && test "$(readlink /usr/bin/docker)" = /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker && test ! -x /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker') 8
    return [pscustomobject]@{Ready=$false;EngineReady=($windows.ExitCode -eq 0);
        SharedToolsMissing=($missing.ExitCode -eq 0);EngineMismatch=($bothReady -and $linuxId -ne $windowsId);
        Detail=$linux.Output;
        WindowsDetail=$windows.Output}
}

function Get-DockerDesktopSettingsFile {
    foreach ($name in @('settings-store.json', 'settings.json')) {
        $path = Join-Path $env:APPDATA "Docker\$name"
        if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    }
    return ''
}

function Get-DockerWslSettings([string]$file, [string]$distro, [string[]]$registered) {
    # Returns Docker Desktop's settings with the selected distribution enabled
    # and entries for unregistered distributions dropped, plus whether they differ.
    $settings = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $listName = if ((Split-Path -Leaf $file) -eq 'settings.json') { 'integratedWslDistros' } else { 'IntegratedWslDistros' }
    $current = @($settings.$listName | Where-Object { $_ })
    $wanted = @(@($current | Where-Object { $_ -in $registered }) + $distro | Select-Object -Unique)
    $changed = ($current -join "`n") -ne ($wanted -join "`n")
    if ($changed) { $settings | Add-Member -NotePropertyName $listName -NotePropertyValue $wanted -Force }
    # These keys are only present on versions and setups that use them.
    foreach ($required in @(@{Name='EngineTypeWindows';Value='wsl2'}, @{Name='WslEngineEnabled';Value=$true},
            @{Name='UseWindowsContainers';Value=$false})) {
        $property = $settings.PSObject.Properties[$required.Name]
        if ($property -and $property.Value -ne $required.Value) {
            $property.Value = $required.Value
            $changed = $true
        }
    }
    return [pscustomobject]@{Settings=$settings;Changed=$changed}
}

function Save-DockerDesktopSettings([string]$file, [object]$settings) {
    $temporary = "$file.ctf-agent"
    $json = $settings | ConvertTo-Json -Depth 32
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $file -Force
}

function Stop-DockerDesktopForSettings {
    $docker = Get-DesktopDockerCli
    $active = Invoke-DesktopNative $docker @('--context', 'desktop-linux', 'ps', '-q') 8
    if ($active.ExitCode -eq 0 -and $active.Output.Trim()) {
        throw 'Docker Desktop must restart to connect this WSL distribution, but containers are running, so it was not restarted. Stop them when safe, then rerun Install.cmd.'
    }
    Write-Host 'Stopping Docker Desktop to apply its WSL integration settings...'
    $stop = Invoke-DesktopNative $docker @('desktop', 'stop', '--timeout', '60') 70
    if ($stop.ExitCode -ne 0) { throw "Docker Desktop could not be stopped: $($stop.Output)" }
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if (-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Seconds 1
    }
    throw 'Docker Desktop did not exit after it was stopped.'
}

function Ensure-DockerWslIntegration([string]$distro, [string[]]$registered, [string]$desktop,
    [bool]$reconnect = $false) {
    # Docker Desktop reads WSL Integration settings when it starts, so changing
    # them means editing the file while it is stopped.
    $running = [bool](Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)
    $file = Get-DockerDesktopSettingsFile
    if (-not $file) {
        if (-not $running) { Start-Process -FilePath $desktop; $running = $true }
        Write-Host 'Waiting for the first Docker Desktop start. Accept its license window if it appears.'
        for ($attempt = 0; $attempt -lt 300 -and -not $file; $attempt++) {
            Start-Sleep -Seconds 1
            $file = Get-DockerDesktopSettingsFile
        }
        if (-not $file) { throw 'Docker Desktop did not finish its first start. Open it once, then rerun Install.cmd.' }
    }
    $plan = Get-DockerWslSettings $file $distro $registered
    if ($running -and -not $reconnect -and (Get-WslDockerState $distro).Ready) {
        if (-not $plan.Changed) { return }
        # It works through the default-distribution option, which ends if the
        # Windows default changes. Listing it is not worth stopping containers.
        $docker = Get-DesktopDockerCli
        $active = Invoke-DesktopNative $docker @('--context', 'desktop-linux', 'ps', '-q') 8
        if ($active.ExitCode -ne 0 -or $active.Output.Trim()) { return }
    }
    if ($running -and ($plan.Changed -or $reconnect)) {
        Stop-DockerDesktopForSettings
        $running = $false
        $plan = Get-DockerWslSettings $file $distro $registered
    }
    if ($plan.Changed) {
        Write-Host "Enabling Docker Desktop WSL integration for $distro."
        Save-DockerDesktopSettings $file $plan.Settings
    }
    if (-not $running) { Start-Process -FilePath $desktop }
}

function Remove-OrphanedCtfAgentContainers {
    # Docker Desktop keeps the containers of an unregistered distribution, and
    # installing elsewhere refuses a web container that has a different data
    # path. Their bind mounts and data went with that distribution.
    $docker = Get-DesktopDockerCli
    $ids = @()
    foreach ($filter in @('label=com.docker.compose.project=ctf_agent_local', 'name=^ctf_agent_local_updater$')) {
        $listed = Invoke-DesktopNative $docker @('--context', 'desktop-linux', 'ps', '-aq', '--filter', $filter) 15
        if ($listed.ExitCode -ne 0) { throw "Could not list old CTF Agent containers: $($listed.Output)" }
        $ids += @($listed.Stdout -split '\s+' | Where-Object { $_ })
    }
    if (-not $ids.Count) { return }
    Write-Host "Removing $($ids.Count) container(s) left by the removed distribution."
    $removed = Invoke-DesktopNative $docker (@('--context', 'desktop-linux', 'rm', '-f') + $ids) 60
    if ($removed.ExitCode -ne 0) { throw "Could not remove old CTF Agent containers: $($removed.Output)" }
    Invoke-DesktopNative $docker @('--context', 'desktop-linux', 'network', 'rm',
        'ctf_agent_local_solver_egress', 'ctf_agent_local_default') 30 | Out-Null
}

function Wait-WslDockerReady([string]$distro, [int]$timeoutSeconds = 90,
    [switch]$AllowRepair) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $repaired = $false
    $state = $null
    while ($watch.Elapsed.TotalSeconds -lt $timeoutSeconds) {
        $state = Get-WslDockerState $distro
        if ($state.Ready) { return }
        if ($state.EngineMismatch) {
            throw "The selected WSL distribution is connected to a different Docker Engine. Its existing containers were not changed. Rerun Install.cmd and choose N for a dedicated Ubuntu distribution, then enable Docker Desktop WSL Integration for that distribution."
        }
        # An engine that stays up without reaching this distribution will not
        # recover alone, for example after "Skip WSL distro integration".
        $stalled = $state.SharedToolsMissing -or $watch.Elapsed.TotalSeconds -ge 60
        if ($state.EngineReady -and $stalled -and $AllowRepair -and -not $repaired) {
            $docker = Get-DesktopDockerCli
            $active = Invoke-DesktopNative $docker @('--context', 'desktop-linux', 'ps', '-q') 8
            if ($active.ExitCode -ne 0 -or $active.Output.Trim()) {
                throw "Docker's WSL integration is not working in $distro. Active containers exist or their state is unknown, so Docker Desktop was not restarted. Restart Docker Desktop when safe, then retry. Updating WSL fixes the cross-distribution shutdown issue (microsoft/WSL#41084)."
            }
            Write-Host "Docker engine is running, but its WSL integration is not working in $distro."
            Write-Host 'No containers are running. Restarting Docker Desktop once to restore WSL integration...'
            $repaired = $true
            $restart = Invoke-DesktopNative $docker @('desktop', 'restart', '--timeout', '45') 50
            if ($restart.ExitCode -ne 0) {
                throw "Docker Desktop recovery failed: $($restart.Output)"
            }
            continue
        }
        if ($state.EngineReady -and $state.SharedToolsMissing) { break }
        Start-Sleep -Seconds 2
    }
    $detail = if ($state) { $state.Detail } else { 'Docker readiness check did not complete.' }
    $windowsDetail = if ($state) { $state.WindowsDetail } else { '' }
    throw "Docker is unavailable inside $distro. WSL error: $detail`nWindows engine: $windowsDetail`nIf WSL integration is disabled, enable Docker Desktop > Settings > Resources > WSL Integration for $distro. A missing shared CLI mount requires Docker Desktop recovery or a WSL update; repeatedly enabling an already enabled switch will not repair it."
}

function Wait-CtfAgentReady([string]$distro, [string]$linuxHome, [int]$timeoutSeconds = 60) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $workerProbe = @'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])/'ctf_agent_data/solver-exchange/slots/solver-1/worker.json'
d={}
if p.is_file() and not p.is_symlink() and p.stat().st_size<65536:
    d=json.loads(p.read_text())
print(json.dumps({'ready':d.get('ready'), 'reason':d.get('reason')}))
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($workerProbe))
    $program = 'import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))'
    while ($watch.Elapsed.TotalSeconds -lt $timeoutSeconds) {
        try {
            $response = Invoke-WebRequest -Uri 'http://127.0.0.1:5050/readyz' -UseBasicParsing -TimeoutSec 5
            if ([int]$response.StatusCode -eq 200) { return }
        } catch { }
        $docker = Get-DesktopDockerCli
        $worker = Invoke-DesktopNative $docker @('--context','desktop-linux','inspect',
            'ctf_agent_local_solver','--format','{{.State.Status}}') 8
        if ($worker.ExitCode -eq 0 -and $worker.Output.Trim() -eq 'exited') {
            $probe = Invoke-DesktopNative 'wsl.exe' @('--distribution',$distro,'--exec',
                'python3','-c',$program,$encoded,$linuxHome) 10
            $reason = 'unknown worker startup failure'
            if ($probe.ExitCode -eq 0) {
                try {
                    $status = $probe.Stdout | ConvertFrom-Json
                    if ($status.reason) { $reason = [string]$status.reason }
                } catch { }
            }
            throw "CTF Agent files and database are installed, but its worker is not ready: $reason. /readyz did not return HTTP 200. Inspect the worker sandbox diagnostics before using the service; installation settings and the database were preserved."
        }
        Start-Sleep -Seconds 2
    }
    throw 'CTF Agent is configured but /readyz did not return HTTP 200 within the readiness deadline. Installation settings and the database were preserved.'
}

function Get-CtfAgentListenAddress([string]$distro, [string]$linuxHome) {
    $config = Invoke-DesktopNative 'wsl.exe' @('--distribution', $distro, '--exec', 'cat', "$linuxHome/.local-config.json") 15
    if ($config.ExitCode -ne 0) { return '127.0.0.1' }
    $address = [string]($config.Stdout | ConvertFrom-Json).listen_address
    if ($address) { return $address }
    return '127.0.0.1'
}

function Ensure-CtfAgentFirewallRule {
    # A forwarded connection still has to pass Windows Firewall on this computer.
    $name = 'CTF Agent 5050'
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { return }
    Write-Host 'Requesting administrator access to allow TCP 5050 through Windows Firewall.'
    $command = "New-NetFirewallRule -DisplayName '$name' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5050 -Profile Any"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $failure = 'Windows Firewall still blocks TCP 5050, so other devices cannot connect. Rerun Install.cmd and approve the administrator prompt.'
    try {
        $process = Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -EncodedCommand $encoded" `
            -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        if ($process.ExitCode -ne 0) { Write-Warning $failure }
    } catch { Write-Warning $failure }
}

function Remove-CtfAgentFirewallRule {
    $name = 'CTF Agent 5050'
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) { return }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Remove-NetFirewallRule -DisplayName '$name'"))
    try { Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -EncodedCommand $encoded" -Verb RunAs -WindowStyle Hidden -Wait }
    catch { Write-Warning "Remove the Windows Firewall rule named $name when convenient." }
}

function Get-CtfAgentLocalTicket([string]$distro, [string]$linuxHome) {
    # The installation key stays in the POST body. Only a one-use, short-lived
    # ticket appears in the URL fragment, which app.js immediately removes.
    $path = "$linuxHome/ctf_agent_data/config/local-access.key"
    $probe = Invoke-DesktopNative 'wsl.exe' @('--distribution', $distro, '--exec',
        'cat', $path) 10
    if ($probe.ExitCode -ne 0 -or $probe.Stdout -notmatch '^[A-Za-z0-9_-]{64}$') {
        throw 'Local browser access is unavailable. Run Install.cmd from this release to repair the installation.'
    }
    try {
        $body = @{ token = $probe.Stdout.Trim() } | ConvertTo-Json -Compress
        $ticketResponse = Invoke-RestMethod -Uri 'http://127.0.0.1:5050/api/auth/local/ticket' `
            -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10
    } catch {
        throw 'Local browser access could not be prepared. Retry Start.cmd after the service is ready.'
    }
    $ticket = [string]$ticketResponse.ticket
    if ($ticket -notmatch '^[A-Za-z0-9_-]{32}$') { throw 'Local browser access returned an invalid ticket.' }
    return $ticket
}

function Open-CtfAgentLocalBrowser([string]$distro, [string]$linuxHome) {
    Start-Process -FilePath ('http://127.0.0.1:5050/#/local-access/' + (Get-CtfAgentLocalTicket $distro $linuxHome))
}
