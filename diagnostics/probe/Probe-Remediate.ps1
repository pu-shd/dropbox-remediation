<#
.SYNOPSIS
    Intune Remediation probe - REMEDIATION script. Needs no privileges.

.DESCRIPTION
    Writes a timestamp to a marker file in the running context's own temp folder
    and reports the context. That is the only change it makes. Pair it with
    Probe-Detect.ps1.
#>
$ErrorActionPreference = 'Stop'

function Get-ProbeContext {
    $who = "$env:USERDOMAIN\$env:USERNAME"
    try { $who = [string](whoami) } catch { }

    $arch = '64-bit host'
    if ($env:PROCESSOR_ARCHITEW6432) {
        $arch = '32-bit host on 64-bit OS'
    } elseif ($env:PROCESSOR_ARCHITECTURE -eq 'x86') {
        $arch = '32-bit'
    }

    $session = '?'
    try { $session = (Get-Process -Id $PID).SessionId } catch { }

    $lang = 'Unknown'
    try { $lang = [string]$ExecutionContext.SessionState.LanguageMode } catch { }

    return ('user={0} | {1} | ps={2} | lang={3} | session={4}' -f $who, $arch, $PSVersionTable.PSVersion, $lang, $session)
}

function Get-ProbeMarkerPath {
    $dir = $env:TEMP
    if (-not $dir) { $dir = $env:TMPDIR }
    if (-not $dir) { $dir = '/tmp' }
    return (Join-Path $dir 'IntuneRemediationProbe.marker')
}

try {
    $marker = Get-ProbeMarkerPath
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Set-Content -LiteralPath $marker -Value $stamp -Encoding ASCII
    Write-Output ('PROBE REMEDIATED: wrote {0} | {1}' -f $marker, (Get-ProbeContext))
    exit 0
} catch {
    Write-Output ('PROBE ERROR in remediation: {0}' -f $_.Exception.Message)
    exit 1
}
