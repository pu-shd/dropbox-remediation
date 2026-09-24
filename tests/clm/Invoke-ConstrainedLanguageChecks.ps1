<#
.SYNOPSIS
    Exercises the watchdog payload inside a real ConstrainedLanguage runspace.

.DESCRIPTION
    Run as a child process by ConstrainedLanguage.Tests.ps1. Language mode can only be
    tightened, never relaxed, so this cannot share a process with the rest of the suite.

    This is not a simulation: it sets the runspace to ConstrainedLanguage and then calls
    the real payload functions, which is the same restriction AppLocker script
    enforcement and WDAC impose on a standard user.

    Emits one "PASS <name>" or "FAIL <name>: <reason>" line per check, plus a final
    "CHECKS <n>" line so the caller can prove checks actually ran.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PayloadPath,
    [Parameter(Mandatory = $true)][string]$Sandbox
)

$ErrorActionPreference = 'Continue'
$Script:Checks = 0

function Check {
    param([string]$Name, [scriptblock]$Body)
    $Script:Checks++
    try {
        $result = & $Body
        if ($result -eq $true) {
            Write-Output "PASS $Name"
        } else {
            Write-Output ("FAIL {0}: returned '{1}'" -f $Name, $result)
        }
    } catch {
        Write-Output ("FAIL {0}: {1}" -f $Name, ($_.Exception.Message -split "`n")[0])
    }
}

# --- sandbox ---
$env:ProgramData  = Join-Path $Sandbox 'ProgramData'
$env:LOCALAPPDATA = Join-Path $Sandbox 'LocalAppData'
$root = Join-Path $env:ProgramData 'DropboxWatchdog'
New-Item -ItemType Directory -Path (Join-Path $root 'bin') -Force | Out-Null
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
$env:DBW_TEST_IMPORT = '1'

# --- lock it down BEFORE loading anything ---
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'

Check 'runspace is actually constrained' {
    $ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage'
}

Check 'payload dot-sources under ConstrainedLanguage' {
    . $PayloadPath
    (Get-Command Invoke-WatchdogCycle -ErrorAction SilentlyContinue) -ne $null
}

. $PayloadPath

# --- test doubles, defined after the dot-source so they shadow the real ones ---
$Script:Launched = 0
$Script:DropboxAlive = $false
function Get-CurrentSessionId { return 1 }
function Get-ProcessByName {
    param($Name)
    if ($Name -eq 'explorer') { return @(@{ Name = 'explorer'; SessionId = 1 }) }
    if ($Name -eq 'Dropbox' -and $Script:DropboxAlive) { return @(@{ Name = 'Dropbox'; SessionId = 1 }) }
    return @()
}
function Get-DropboxLaunchTarget {
    return @{ Path = 'C:\Users\a\AppData\Local\Dropbox\bin\Dropbox.exe'; Arguments = @('/systemstartup'); Source = 'test' }
}
function Start-DropboxProcess { param($Target) $Script:Launched++; $Script:DropboxAlive = $true }
function Write-WatchdogEvent { param($Message, $EntryType, $EventId) return $true }
function Get-DropboxCrashEvidence { param($LookbackMinutes) return 'Application Error/1000: Dropbox.exe' }
function Start-Sleep { param($Seconds) }

# --- the primitives that ConstrainedLanguage actually breaks ---
Check 'Get-PowerShellLanguageMode reports the real mode' {
    (Get-PowerShellLanguageMode) -eq 'ConstrainedLanguage'
}

Check 'Get-WatchdogPaths builds paths without [pscustomobject]' {
    $paths = Get-WatchdogPaths -Root $root
    ($paths.LogPath -like '*watchdog.log') -and ($paths.LockPath -like '*watchdog.lock')
}

Check 'Get-WatchdogConfig returns usable defaults' {
    $config = Get-WatchdogConfig -ConfigPath (Join-Path $root 'bin/version.json')
    ([int]$config.PollSeconds -eq 45) -and ($config.Enabled -eq $true)
}

Check 'Get-WatchdogConfig merges deployed overrides' {
    $configPath = Join-Path $root 'bin/version.json'
    Set-Content -LiteralPath $configPath -Value (@{ PollSeconds = 90; MaxRestartsPerHour = 2 } | ConvertTo-Json)
    $config = Get-WatchdogConfig -ConfigPath $configPath
    ([int]$config.PollSeconds -eq 90) -and ([int]$config.MaxRestartsPerHour -eq 2)
}

Check 'Initialize-Watchdog succeeds' {
    Initialize-Watchdog -Root $root | Out-Null
    $Script:Paths -ne $null
}

Check 'Split-CommandLine works without StringBuilder' {
    $tokens = @(Split-CommandLine -CommandLine '"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe" /systemstartup')
    ($tokens.Count -eq 2) -and ($tokens[0] -eq 'C:\Program Files (x86)\Dropbox\Client\Dropbox.exe')
}

Check 'ConvertFrom-DropboxCommandLine returns a usable target' {
    $target = ConvertFrom-DropboxCommandLine -CommandLine '"C:\dbx\Dropbox.exe" /systemstartup' -Source 'test'
    $target.Path -eq 'C:\dbx\Dropbox.exe'
}

Check 'Get-DropboxCandidate builds the candidate list without a generic List' {
    $candidates = @(Get-DropboxCandidate)
    $candidates.Count -gt 0 -and $candidates[0].Path -ne $null
}

Check 'Write-WatchdogLog writes to the per-user log' {
    Write-WatchdogLog -Message 'constrained mode smoke test' -Level 'Info'
    (Get-Content -LiteralPath $Script:Paths.LogPath -Raw) -match 'constrained mode smoke test'
}

Check 'Invoke-LogRotation reads file length' {
    Set-Content -LiteralPath $Script:Paths.LogPath -Value ('x' * 3000)
    Invoke-LogRotation -LogPath $Script:Paths.LogPath -MaxBytes 1024
    Test-Path -LiteralPath ($Script:Paths.LogPath + '.1')
}

Check 'state round-trips through JSON' {
    $state = Get-WatchdogState
    $state['ConsecutiveFailures'] = 4
    Save-WatchdogState -State $state | Out-Null
    $reloaded = Get-WatchdogState
    [int]$reloaded.ConsecutiveFailures -eq 4
}

Check 'state records the language mode for remote reporting' {
    $state = Get-WatchdogState
    Save-WatchdogState -State $state | Out-Null
    $raw = Get-Content -LiteralPath $Script:Paths.StatePath -Raw | ConvertFrom-Json
    $raw.LanguageMode -eq 'ConstrainedLanguage'
}

Check 'timestamp parsing and pruning work' {
    $now = (Get-Date).ToUniversalTime()
    $state = @{ RestartHistoryUtc = @($now.AddMinutes(-5).ToString('o'), $now.AddMinutes(-120).ToString('o')) }
    (Get-RecentRestartCount -State $state -NowUtc $now) -eq 1
}

Check 'backoff ladder works' {
    (Get-BackoffSeconds -ConsecutiveFailures 3 -BackoffSeconds @(5, 15, 60)) -eq 60
}

Check 'session lock can be taken and released' {
    Remove-Item -LiteralPath $Script:Paths.LockPath -Force -ErrorAction SilentlyContinue
    $taken = Set-WatchdogLock
    $ownerWhileHeld = Get-WatchdogLockOwner      # our own PID must not count as a rival
    $released = Remove-WatchdogLock
    $taken -and ($null -eq $ownerWhileHeld) -and $released
}

Check 'a stale lock from a dead process is reclaimed' {
    Set-Content -LiteralPath $Script:Paths.LockPath -Value '999999'
    $null -eq (Get-WatchdogLockOwner)
}

# --- the whole cycle, end to end ---
Check 'cycle reports Running when Dropbox is alive' {
    $Script:DropboxAlive = $true
    (Invoke-WatchdogCycle) -eq 'Running'
}

Check 'cycle relaunches Dropbox when it has exited' {
    $Script:DropboxAlive = $false
    $Script:Launched = 0
    $result = Invoke-WatchdogCycle
    ($result -eq 'Restarted') -and ($Script:Launched -eq 1)
}

Check 'cycle honours the pause marker' {
    Set-Content -LiteralPath $Script:Paths.MachinePauseMarker -Value ''
    $result = Invoke-WatchdogCycle
    Remove-Item -LiteralPath $Script:Paths.MachinePauseMarker -Force
    $result -eq 'Paused'
}

Check 'cycle throttles a crash loop' {
    $now = (Get-Date).ToUniversalTime()
    $state = Get-WatchdogState
    $state['RestartHistoryUtc'] = @(1..10 | ForEach-Object { $now.AddMinutes(-1 * $_).ToString('o') })
    Save-WatchdogState -State $state | Out-Null
    $Script:DropboxAlive = $false
    $Script:Launched = 0
    $result = Invoke-WatchdogCycle
    ($result -eq 'Throttled') -and ($Script:Launched -eq 0)
}

Write-Output "CHECKS $Script:Checks"
