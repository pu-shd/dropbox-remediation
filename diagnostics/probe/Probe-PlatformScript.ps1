<#
.SYNOPSIS
    Intune PLATFORM script probe. Needs no privileges.

.DESCRIPTION
    Deploy this under Scripts and remediations > Platform scripts, not under
    Remediations. Platform scripts are a separate Intune feature that does not
    depend on the Windows licence attestation Remediations requires, so whether
    this one saves and assigns to the same group tells you whether the problem is
    specific to Remediations.

    The portal only shows success or failure for platform scripts, not output, so
    this also writes a log line to its own temp folder.
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

try {
    $dir = $env:TEMP
    if (-not $dir) { $dir = $env:TMPDIR }
    if (-not $dir) { $dir = '/tmp' }
    $log = Join-Path $dir 'IntunePlatformScriptProbe.log'
    $line = '{0} PROBE PLATFORM SCRIPT RAN | {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), (Get-ProbeContext)
    Add-Content -LiteralPath $log -Value $line -Encoding ASCII
    Write-Output $line
    exit 0
} catch {
    Write-Output ('PROBE ERROR in platform script: {0}' -f $_.Exception.Message)
    exit 1
}
