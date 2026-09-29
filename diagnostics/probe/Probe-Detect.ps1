<#
.SYNOPSIS
    Intune Remediation probe - DETECTION script. Needs no privileges.

.DESCRIPTION
    Used to find out why a remediation package will not save or assign. It does
    nothing except report the context it ran in. It exits 1 until the paired
    remediation has run once, so both halves of the package get exercised, then
    exits 0 from then on.

    It works the same as SYSTEM or as the signed-in user, in 32- or 64-bit
    PowerShell, and under ConstrainedLanguage.
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
    # $env:TEMP differs by context (SYSTEM gets C:\Windows\SystemTemp or
    # C:\Windows\Temp, a user gets their profile temp), so each context gets its
    # own marker and the two packages cannot interfere with each other.
    $dir = $env:TEMP
    if (-not $dir) { $dir = $env:TMPDIR }
    if (-not $dir) { $dir = '/tmp' }
    return (Join-Path $dir 'IntuneRemediationProbe.marker')
}

try {
    $marker = Get-ProbeMarkerPath
    $context = Get-ProbeContext
    if (Test-Path -LiteralPath $marker) {
        $when = ([string](Get-Content -LiteralPath $marker -Raw)).Trim()
        Write-Output ('PROBE COMPLIANT: remediation ran at {0} | {1}' -f $when, $context)
        exit 0
    }
    Write-Output ('PROBE NOT_COMPLIANT: no marker yet, remediation should run | {0}' -f $context)
    exit 1
} catch {
    Write-Output ('PROBE ERROR in detection: {0}' -f $_.Exception.Message)
    exit 1
}
