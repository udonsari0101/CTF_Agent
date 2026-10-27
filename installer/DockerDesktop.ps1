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
        '--exec', 'docker', 'info', '--format', '{{.ServerVersion}}') 12
    if ($linux.ExitCode -eq 0) {
        return [pscustomobject]@{Ready=$true;EngineReady=$true;SharedToolsMissing=$false;
            Detail=$linux.Output;WindowsDetail=''}
    }
    $docker = Get-DesktopDockerCli
    # Always inspect the local Desktop engine, never a user's remote context.
    $windows = Invoke-DesktopNative $docker @('--context', 'desktop-linux',
        'info', '--format', '{{.ServerVersion}}') 8
    $missing = Invoke-DesktopNative 'wsl.exe' @('--distribution', $distro, '--exec',
        '/bin/sh', '-c', 'test -L /usr/bin/docker && test "$(readlink /usr/bin/docker)" = /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker && test ! -x /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker') 8
    return [pscustomobject]@{Ready=$false;EngineReady=($windows.ExitCode -eq 0);
        SharedToolsMissing=($missing.ExitCode -eq 0);Detail=$linux.Output;
        WindowsDetail=$windows.Output}
}

function Wait-WslDockerReady([string]$distro, [int]$timeoutSeconds = 90,
    [switch]$AllowRepair) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $repaired = $false
    $state = $null
    while ($watch.Elapsed.TotalSeconds -lt $timeoutSeconds) {
        $state = Get-WslDockerState $distro
        if ($state.Ready) { return }
        if ($state.EngineReady -and $state.SharedToolsMissing) {
            if (-not $AllowRepair -or $repaired) { break }
            $docker = Get-DesktopDockerCli
            $active = Invoke-DesktopNative $docker @('--context', 'desktop-linux', 'ps', '-q') 8
            if ($active.ExitCode -ne 0 -or $active.Output.Trim()) {
                throw "Docker's shared WSL CLI mount is missing in $distro. Active containers exist or their state is unknown, so Docker Desktop was not restarted. Restart Docker Desktop when safe, then retry. Updating WSL fixes the cross-distribution shutdown issue (microsoft/WSL#41084)."
            }
            Write-Host 'Docker engine is running, but its shared WSL CLI mount is missing.'
            Write-Host 'No containers are running. Restarting Docker Desktop once to restore WSL integration...'
            $repaired = $true
            $restart = Invoke-DesktopNative $docker @('desktop', 'restart', '--timeout', '45') 50
            if ($restart.ExitCode -ne 0) {
                throw "Docker Desktop recovery failed: $($restart.Output)"
            }
            continue
        }
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
