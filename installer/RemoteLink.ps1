param([string]$Address = '')

if ($env:CTF_AGENT_LAUNCH_MARKER) { [IO.File]::WriteAllText($env:CTF_AGENT_LAUNCH_MARKER, '') }

# Prints a one-use link that connects another device's browser to a no-login
# installation. The ticket expires after 90 seconds, and the browser it connects
# stays connected for 30 days.
$ErrorActionPreference = 'Stop'
$dockerDesktopHelper = Join-Path $PSScriptRoot 'DockerDesktop.ps1'
if (-not (Test-Path -LiteralPath $dockerDesktopHelper -PathType Leaf)) { throw 'DockerDesktop.ps1 is missing. Reinstall the patched release.' }
. $dockerDesktopHelper

$stateFile = Join-Path $env:LOCALAPPDATA 'CTF Agent\install.json'
if (-not (Test-Path -LiteralPath $stateFile -PathType Leaf)) { throw 'CTF Agent installation settings are missing. Run Install.cmd first.' }
$saved = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$saved.authMode -ne 'nologin') {
    Write-Host 'This installation uses accounts. Sign in on the other device instead.'
    exit 0
}
if ((Get-CtfAgentListenAddress ([string]$saved.distro) ([string]$saved.home)) -ne '0.0.0.0') {
    throw 'CTF Agent accepts this computer only. Rerun Install.cmd with -ListenAddress 0.0.0.0 first.'
}
if (-not $Address -and @($saved.public_urls).Count -and [string]@($saved.public_urls)[0]) {
    $Address = [string]@($saved.public_urls)[0]
    Write-Host 'Using the configured public address.'
} elseif (-not $Address) {
    # VPN adapters can have gateways too, so follow the preferred default route.
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object {
        $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric
    } | Select-Object -First 1
    $Address = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 | Select-Object -First 1).IPAddress
    Write-Host "Using this computer's network address. From outside your network, pass your public address instead."
}
$origin = ''
$uri = $null
if ([Uri]::TryCreate($Address, [UriKind]::Absolute, [ref]$uri)) {
    if ($uri.Scheme -notin @('http', 'https') -or -not $uri.Host -or
        $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') {
        throw 'Enter an HTTP(S) origin without a path, query or credentials.'
    }
    $origin = $uri.GetLeftPart([UriPartial]::Authority).TrimEnd('/')
} elseif ($Address -match '^[A-Za-z0-9.\[\]-]+$') {
    $origin = "http://$Address`:5050"
} else {
    throw 'Enter a host name, IP address or full HTTP(S) origin.'
}
if ([string]$saved.access_mode -eq 'open') {
    Write-Host 'Open this address on the other device:'
    Write-Host "$origin/"
    exit 0
}
$ticket = Get-CtfAgentLocalTicket ([string]$saved.distro) ([string]$saved.home)
Write-Host 'Open this link on the other device within 90 seconds. It works once.'
Write-Host "$origin/#/local-access/$ticket"
