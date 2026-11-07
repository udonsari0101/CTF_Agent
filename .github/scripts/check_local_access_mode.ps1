$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot '..\..\installer\Install.ps1'
$source = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $installer))
$begin = $source.IndexOf('$accessMode = if ($PSBoundParameters.ContainsKey(''OpenAccess''))')
if ($begin -lt 0) { throw 'The installer access-mode selection was not found.' }
$end = $source.IndexOf("`nif (`$accessMode -eq 'open'", $begin)
if ($end -le $begin) { throw 'The installer access-mode selection is incomplete.' }
$selection = $source.Substring($begin, $end - $begin)

function Select-InstallerAccessMode {
    param(
        [string]$authMode,
        [string]$ListenAddress,
        [string[]]$publicUrls,
        [object]$saved,
        [switch]$OpenAccess
    )
    Invoke-Expression $selection
    return $accessMode
}

function Assert-AccessMode([string]$expected, [string]$actual, [string]$caseName) {
    if ($actual -ne $expected) {
        throw "$caseName selected $actual, expected $expected."
    }
}

Assert-AccessMode 'link' (Select-InstallerAccessMode 'nologin' '127.0.0.1' @() $null) 'Local-only default'
Assert-AccessMode 'open' (Select-InstallerAccessMode 'nologin' '0.0.0.0' @() $null) 'LAN default'
Assert-AccessMode 'open' (Select-InstallerAccessMode 'nologin' '127.0.0.1' @('https://ctf.example.test') $null) 'Public URL default'
Assert-AccessMode 'open' (Select-InstallerAccessMode 'nologin' '0.0.0.0' @() ([pscustomobject]@{access_mode='link'})) 'Legacy link upgrade'
Assert-AccessMode 'open' (Select-InstallerAccessMode 'nologin' '127.0.0.1' @() ([pscustomobject]@{access_mode='open'})) 'Saved open preference'
Assert-AccessMode 'link' (Select-InstallerAccessMode 'password' '0.0.0.0' @() $null) 'Password login'
Assert-AccessMode 'link' (Select-InstallerAccessMode 'nologin' '0.0.0.0' @() $null -OpenAccess:$false) 'Explicit link preference'
Write-Host 'PASS: local-only access stays paired, external no-login access opens directly, password login stays protected'
