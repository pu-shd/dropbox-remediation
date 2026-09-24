<#
.SYNOPSIS
    Per-user, in-session watchdog that keeps the Dropbox client running.

.DESCRIPTION
    Deployed to C:\ProgramData\DropboxWatchdog\bin by the Intune remediation script and
    launched by a scheduled task registered against the BUILTIN\Users group, so one
    instance runs inside every interactive user session on the device.

    Responsibilities:
      * Locate Dropbox for THIS user, no matter how it was installed
        (per-user, machine-wide, or Microsoft Store).
      * Detect that Dropbox has exited and relaunch it in the user's own session.
      * Apply crash-loop protection so a genuinely broken client is not respawned
        in a tight loop.
      * Record every action to a per-user log and to the Windows Application event
        log, so the underlying cause can be investigated centrally.

.PARAMETER Mode
    Service : long-running supervisor loop (used by the scheduled task).
    Once    : run a single check and exit (used for manual verification/support).

.NOTES
    Must remain compatible with Windows PowerShell 5.1 (no PS7-only syntax).
#>
[CmdletBinding()]
param(
    [ValidateSet('Service', 'Once')]
    [string]$Mode = 'Once',

    [string]$InstallRoot = "$env:ProgramData\DropboxWatchdog"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Bumped whenever the payload changes; build.sh reads this value and stamps it into
# the detection/remediation scripts so Intune re-deploys the payload on upgrade.
$Script:PayloadVersion = '1.0.0'

# Event IDs written to the Application log (source: DropboxWatchdog).
$Script:EventIds = @{
    ServiceStarted  = 1000
    ServiceStopped  = 1001
    NotInstalled    = 2000
    RestartAttempt  = 2001
    RestartSucceeded= 2002
    RestartFailed   = 3000
    CrashLoop       = 3001
    WatchdogError   = 4000
}

#--------------------------------------------------------------------------------------
# Environment wrappers. Every Windows-only API lives behind one of these so the logic
# above them can be unit-tested on Linux/macOS containers with mocks.
#--------------------------------------------------------------------------------------

function Get-CurrentSessionId {
    [CmdletBinding()]
    param()
    try {
        return (Get-Process -Id $PID).SessionId
    } catch {
        return -1
    }
}

function Get-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        if ($null -eq $item) { return $null }
        if (-not ($item.PSObject.Properties.Name -contains $Name)) { return $null }
        $value = $item.$Name
        if ([string]::IsNullOrWhiteSpace([string]$value)) { return $null }
        return [string]$value
    } catch {
        return $null
    }
}

function Get-ProcessByName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        return @(Get-Process -Name $Name -ErrorAction SilentlyContinue)
    } catch {
        return @()
    }
}

function Get-DropboxAppxTarget {
    [CmdletBinding()]
    param()
    try {
        $cmd = Get-Command -Name 'Get-AppxPackage' -ErrorAction SilentlyContinue
        if (-not $cmd) { return $null }
        $pkg = @(Get-AppxPackage -Name '*Dropbox*' -ErrorAction SilentlyContinue) | Select-Object -First 1
        if (-not $pkg) { return $null }
        return @{
            Path      = "$env:SystemRoot\explorer.exe"
            Arguments = @("shell:AppsFolder\$($pkg.PackageFamilyName)!Dropbox")
            Source    = 'AppxPackage'
        }
    } catch {
        return $null
    }
}

function Write-WatchdogEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')][string]$EntryType = 'Information',
        [Parameter(Mandatory = $true)][int]$EventId
    )
    # Best effort only: the event source is created by the SYSTEM-context remediation
    # script. If it is missing, a standard user cannot create it and we fall back to
    # the per-user log file alone.
    #
    # Prefer the Write-EventLog CMDLET over [System.Diagnostics.EventLog]: cmdlets stay
    # available under ConstrainedLanguage, static .NET calls do not.
    try {
        if (Get-Command -Name 'Write-EventLog' -ErrorAction SilentlyContinue) {
            Write-EventLog -LogName 'Application' -Source 'DropboxWatchdog' `
                -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction Stop
            return $true
        }
    } catch {
        return $false
    }

    # PowerShell 7 has no Write-EventLog; fall back to .NET where the language mode allows it.
    try {
        [System.Diagnostics.EventLog]::WriteEntry(
            'DropboxWatchdog',
            $Message,
            [System.Diagnostics.EventLogEntryType]$EntryType,
            $EventId)
        return $true
    } catch {
        return $false
    }
}

function Start-DropboxProcess {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Target)

    $params = @{
        FilePath    = $Target.Path
        ErrorAction = 'Stop'
    }
    if ($Target.Arguments -and @($Target.Arguments).Count -gt 0) {
        $params['ArgumentList'] = @($Target.Arguments)
    }
    $workingDir = Split-Path -Parent $Target.Path
    if ($workingDir -and (Test-Path -LiteralPath $workingDir)) {
        $params['WorkingDirectory'] = $workingDir
    }
    Start-Process @params | Out-Null
}

#--------------------------------------------------------------------------------------
# Paths, configuration and logging
#--------------------------------------------------------------------------------------

function Get-WatchdogPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root)

    $userDir = "$env:LOCALAPPDATA\DropboxWatchdog"
    # Hashtables throughout, not [pscustomobject]: the pscustomobject cast is blocked
    # under ConstrainedLanguage, and this script runs as a standard user.
    @{
        InstallRoot        = $Root
        ConfigPath         = "$Root\bin\version.json"
        PayloadPath        = "$Root\bin\DropboxWatchdog.ps1"
        MachinePauseMarker = "$Root\pause.marker"
        UserDir            = $userDir
        LogPath            = "$userDir\watchdog.log"
        StatePath          = "$userDir\state.json"
        LockPath           = "$userDir\watchdog.lock"
        UserPauseMarker    = "$userDir\pause.marker"
    }
}

function Get-WatchdogConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    $config = [ordered]@{
        PayloadVersion        = $Script:PayloadVersion
        Enabled               = $true
        PollSeconds           = 45
        SettleSeconds         = 20
        HeartbeatStaleMinutes = 90
        MaxRestartsPerHour    = 6
        BackoffSeconds        = @(5, 15, 60, 300, 900)
        MaxLogBytes           = 1048576
        ServiceMaxHours       = 24
    }

    try {
        if (Test-Path -LiteralPath $ConfigPath) {
            $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $json = $raw | ConvertFrom-Json
                $names = @($json.PSObject.Properties.Name)
                foreach ($key in @($config.Keys)) {
                    if ($names -contains $key) {
                        $value = $json.$key
                        if ($null -ne $value) { $config[$key] = $value }
                    }
                }
            }
        }
    } catch {
        # A malformed config must never stop the watchdog; defaults are safe.
    }

    # Clamp to sane bounds so a bad config cannot busy-spin or disable monitoring.
    if ([int]$config['PollSeconds'] -lt 15)   { $config['PollSeconds'] = 15 }
    if ([int]$config['PollSeconds'] -gt 3600) { $config['PollSeconds'] = 3600 }
    if ([int]$config['SettleSeconds'] -lt 1)  { $config['SettleSeconds'] = 1 }
    if ([int]$config['MaxRestartsPerHour'] -lt 1) { $config['MaxRestartsPerHour'] = 1 }

    return $config
}

function Initialize-Watchdog {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root)

    $Script:Paths  = Get-WatchdogPaths -Root $Root
    $Script:Config = Get-WatchdogConfig -ConfigPath $Script:Paths.ConfigPath
    try {
        if (-not (Test-Path -LiteralPath $Script:Paths.UserDir)) {
            New-Item -ItemType Directory -Path $Script:Paths.UserDir -Force | Out-Null
        }
    } catch {
        # Logging degrades to event log only.
    }
    return $Script:Paths
}

function Invoke-LogRotation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LogPath, [int]$MaxBytes = 1048576)
    try {
        if (-not (Test-Path -LiteralPath $LogPath)) { return }
        $item = Get-Item -LiteralPath $LogPath
        if ($item.Length -lt $MaxBytes) { return }
        $archive = "$LogPath.1"
        if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
        Move-Item -LiteralPath $LogPath -Destination $archive -Force
    } catch {
        # Rotation failure is not fatal.
    }
}

function Write-WatchdogLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Info', 'Warn', 'Error')][string]$Level = 'Info',
        [int]$EventId = 0
    )

    $line = '{0} [{1}] [{2}\{3}] {4}' -f `
        (Get-Date).ToString('yyyy-MM-dd HH:mm:ssK'), $Level, $env:USERDOMAIN, $env:USERNAME, $Message

    try {
        $maxBytes = 1048576
        if ($Script:Config) { $maxBytes = [int]$Script:Config.MaxLogBytes }
        Invoke-LogRotation -LogPath $Script:Paths.LogPath -MaxBytes $maxBytes
        Add-Content -LiteralPath $Script:Paths.LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Fall through to the event log.
    }

    if ($EventId -gt 0) {
        $entryType = 'Information'
        if ($Level -eq 'Warn')  { $entryType = 'Warning' }
        if ($Level -eq 'Error') { $entryType = 'Error' }
        Write-WatchdogEvent -Message $Message -EntryType $entryType -EventId $EventId | Out-Null
    }

    Write-Verbose $line
    # Deliberately returns nothing: callers such as Invoke-WatchdogCycle return a single
    # result string, and a leaked log line would be emitted alongside it.
}

#--------------------------------------------------------------------------------------
# State (heartbeat + restart history). The detection script reads this file to decide
# whether a session's watchdog has wedged.
#--------------------------------------------------------------------------------------

function Get-WatchdogState {
    [CmdletBinding()]
    param()
    $default = @{
        PayloadVersion      = $Script:PayloadVersion
        LanguageMode        = (Get-PowerShellLanguageMode)
        LastCheckUtc        = $null
        LastResult          = 'Unknown'
        LastRestartUtc      = $null
        RestartHistoryUtc   = @()
        ConsecutiveFailures = 0
    }
    try {
        if (-not (Test-Path -LiteralPath $Script:Paths.StatePath)) { return $default }
        $raw = Get-Content -LiteralPath $Script:Paths.StatePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $default }
        $json = $raw | ConvertFrom-Json
        # Reading properties off a ConvertFrom-Json object is permitted under
        # ConstrainedLanguage; only creating one with [pscustomobject] is not.
        $names = @($json.PSObject.Properties.Name)
        foreach ($prop in @($default.Keys)) {
            if ($names -contains $prop) { $default[$prop] = $json.$prop }
        }
        $default['RestartHistoryUtc'] = @($default['RestartHistoryUtc'])
        return $default
    } catch {
        return $default
    }
}

function Save-WatchdogState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State)
    try {
        if (-not (Test-Path -LiteralPath $Script:Paths.UserDir)) {
            New-Item -ItemType Directory -Path $Script:Paths.UserDir -Force | Out-Null
        }
        $State['PayloadVersion'] = $Script:PayloadVersion
        # Recorded so the SYSTEM-context detection script can report, from the portal,
        # whether any session is running constrained - without anyone touching a device.
        $State['LanguageMode'] = Get-PowerShellLanguageMode
        $json = $State | ConvertTo-Json -Depth 4
        Set-Content -LiteralPath $Script:Paths.StatePath -Value $json -Encoding UTF8 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-RecentRestartCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][datetime]$NowUtc,
        [int]$WindowMinutes = 60
    )
    $cutoff = $NowUtc.AddMinutes(-1 * $WindowMinutes)
    $kept = @()
    foreach ($entry in @($State.RestartHistoryUtc)) {
        if ([string]::IsNullOrWhiteSpace([string]$entry)) { continue }
        try {
            $parsed = [datetime]::Parse([string]$entry, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind)
            if ($parsed.ToUniversalTime() -ge $cutoff) { $kept += $parsed.ToUniversalTime().ToString('o') }
        } catch {
            continue
        }
    }
    $State.RestartHistoryUtc = @($kept)
    return @($kept).Count
}

function Get-BackoffSeconds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$ConsecutiveFailures,
        [Parameter(Mandatory = $true)]$BackoffSeconds
    )
    $ladder = @($BackoffSeconds)
    if ($ladder.Count -eq 0) { return 0 }
    if ($ConsecutiveFailures -le 0) { return 0 }
    $index = $ConsecutiveFailures - 1
    if ($index -ge $ladder.Count) { $index = $ladder.Count - 1 }
    return [int]$ladder[$index]
}

#--------------------------------------------------------------------------------------
# Dropbox discovery: cover every supported install shape.
#--------------------------------------------------------------------------------------

function Split-CommandLine {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$CommandLine)

    # Plain arrays and string concatenation only: New-Object on StringBuilder or a
    # generic List is blocked under ConstrainedLanguage.
    $tokens = @()
    $current = ''
    $hasCurrent = $false
    $inQuotes = $false

    foreach ($char in $CommandLine.ToCharArray()) {
        if ($char -eq '"') {
            $inQuotes = -not $inQuotes
            $hasCurrent = $true
            continue
        }
        if ((-not $inQuotes) -and ($char -eq ' ' -or $char -eq "`t")) {
            if ($hasCurrent -and $current -ne '') {
                $tokens += $current
            }
            $current = ''
            $hasCurrent = $false
            continue
        }
        $current += [string]$char
        $hasCurrent = $true
    }
    if ($current -ne '') { $tokens += $current }

    # No unary-comma wrapper: every caller collects with @(...), and the wrapper would
    # nest the result one level deeper instead of preserving it.
    return @($tokens)
}

function ConvertFrom-DropboxCommandLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string]$Source
    )
    $tokens = @(Split-CommandLine -CommandLine $CommandLine)
    if ($tokens.Count -eq 0) { return $null }

    $exe = $tokens[0]
    $argList = @()
    if ($tokens.Count -gt 1) { $argList = @($tokens[1..($tokens.Count - 1)]) }
    if ($argList.Count -eq 0) { $argList = @('/systemstartup') }

    return @{
        Path      = $exe
        Arguments = $argList
        Source    = $Source
    }
}

function Get-DropboxCandidate {
    <#
        Returns every plausible launch target in priority order, without testing
        existence. Get-DropboxLaunchTarget filters to the first one that is real.
    #>
    [CmdletBinding()]
    param()

    $candidates = @()

    # 1. However Dropbox itself starts at logon is the most authoritative answer.
    foreach ($runKey in @(
            @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Source = 'HKCU:Run' },
            @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Source = 'HKLM:Run' })) {
        $value = Get-RegistryValue -Path $runKey.Path -Name 'Dropbox'
        if ($value) {
            $parsed = ConvertFrom-DropboxCommandLine -CommandLine $value -Source $runKey.Source
            if ($parsed) { $candidates += $parsed }
        }
    }

    # 2. Dropbox's own install-path registry values.
    foreach ($installKey in @(
            @{ Path = 'HKCU:\Software\Dropbox'; Source = 'HKCU:Dropbox\InstallPath' },
            @{ Path = 'HKLM:\Software\Dropbox'; Source = 'HKLM:Dropbox\InstallPath' })) {
        $installPath = Get-RegistryValue -Path $installKey.Path -Name 'InstallPath'
        if ($installPath) {
            $trimmed = $installPath.TrimEnd('\')
            foreach ($leaf in @('Dropbox.exe', 'bin\Dropbox.exe', 'Client\Dropbox.exe')) {
                $candidates += @{
                    Path      = "$trimmed\$leaf"
                    Arguments = @('/systemstartup')
                    Source    = $installKey.Source
                }
            }
        }
    }

    # 3. Uninstall entries (covers machine-wide installs and OEM images).
    foreach ($uninstallRoot in @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox')) {
        $location = Get-RegistryValue -Path $uninstallRoot -Name 'InstallLocation'
        if ($location) {
            $trimmed = $location.TrimEnd('\')
            foreach ($leaf in @('Dropbox.exe', 'bin\Dropbox.exe', 'Client\Dropbox.exe')) {
                $candidates += @{
                    Path      = "$trimmed\$leaf"
                    Arguments = @('/systemstartup')
                    Source    = "Uninstall:$uninstallRoot"
                }
            }
        }
    }

    # 4. Well-known filesystem locations, per-user first then machine-wide.
    $wellKnown = @(
        @{ Path = "$env:LOCALAPPDATA\Dropbox\bin\Dropbox.exe";       Source = 'LocalAppData\bin' },
        @{ Path = "$env:LOCALAPPDATA\Dropbox\Client\Dropbox.exe";    Source = 'LocalAppData\Client' },
        @{ Path = "${env:ProgramFiles(x86)}\Dropbox\Client\Dropbox.exe"; Source = 'ProgramFiles(x86)' },
        @{ Path = "$env:ProgramFiles\Dropbox\Client\Dropbox.exe";    Source = 'ProgramFiles' }
    )
    foreach ($entry in $wellKnown) {
        if ([string]::IsNullOrWhiteSpace($entry.Path)) { continue }
        $candidates += @{
            Path      = $entry.Path
            Arguments = @('/systemstartup')
            Source    = $entry.Source
        }
    }

    return @($candidates)
}

function Get-DropboxLaunchTarget {
    [CmdletBinding()]
    param()

    foreach ($candidate in @(Get-DropboxCandidate)) {
        try {
            if ([string]::IsNullOrWhiteSpace($candidate.Path)) { continue }
            if (Test-Path -LiteralPath $candidate.Path -PathType Leaf) { return $candidate }
        } catch {
            continue
        }
    }

    # Last resort: the Microsoft Store packaged client, which has no classic exe path.
    return Get-DropboxAppxTarget
}

#--------------------------------------------------------------------------------------
# Health checks
#--------------------------------------------------------------------------------------

function Test-DropboxRunning {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$SessionId)

    $procs = @(Get-ProcessByName -Name 'Dropbox')
    foreach ($proc in $procs) {
        try {
            if ($proc.SessionId -eq $SessionId) { return $true }
        } catch {
            continue
        }
    }
    return $false
}

function Test-DropboxMaintenanceRunning {
    <# True while a Dropbox installer/updater owns the client; relaunching now would race it. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$SessionId)

    foreach ($name in @('DropboxUpdate', 'DropboxUpdateHelper', 'DropboxInstaller', 'DropboxOfflineInstaller')) {
        foreach ($proc in @(Get-ProcessByName -Name $name)) {
            try {
                if ($proc.SessionId -eq $SessionId) { return $true }
            } catch {
                continue
            }
        }
    }
    return $false
}

function Test-SessionInteractive {
    <#
        Explorer running in our session means the desktop is up. If it is gone the user
        is logging off or the shell crashed, and launching Dropbox would be pointless
        or would block logoff.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$SessionId)

    if ($SessionId -le 0) { return $false }
    foreach ($proc in @(Get-ProcessByName -Name 'explorer')) {
        try {
            if ($proc.SessionId -eq $SessionId) { return $true }
        } catch {
            continue
        }
    }
    return $false
}

function Test-WatchdogPaused {
    [CmdletBinding()]
    param()
    foreach ($marker in @($Script:Paths.MachinePauseMarker, $Script:Paths.UserPauseMarker)) {
        try {
            if (Test-Path -LiteralPath $marker) { return $true }
        } catch {
            continue
        }
    }
    return $false
}

function Get-DropboxCrashEvidence {
    <#
        Pulls the most recent Application-log crash/hang record for Dropbox.exe so the
        restart log line carries a clue about the root cause rather than just "it died".
    #>
    [CmdletBinding()]
    param([int]$LookbackMinutes = 15)

    try {
        $filter = @{
            LogName      = 'Application'
            ProviderName = @('Application Error', 'Application Hang', 'Windows Error Reporting')
            StartTime    = (Get-Date).AddMinutes(-1 * $LookbackMinutes)
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 20 -ErrorAction SilentlyContinue)
        foreach ($event in $events) {
            if ($event.Message -and $event.Message -match 'Dropbox\.exe') {
                $summary = ($event.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' | '
                return ('{0}/{1}: {2}' -f $event.ProviderName, $event.Id, $summary)
            }
        }
    } catch {
        return $null
    }
    return $null
}

#--------------------------------------------------------------------------------------
# Core cycle
#--------------------------------------------------------------------------------------

function Invoke-WatchdogCycle {
    <#
        One monitoring pass. Returns a result string; the caller logs/records it.
        Never throws for expected conditions - the service loop must survive.
    #>
    [CmdletBinding()]
    param()

    $nowUtc = (Get-Date).ToUniversalTime()
    $state = Get-WatchdogState
    $state.LastCheckUtc = $nowUtc.ToString('o')
    $result = 'Unknown'

    try {
        if (-not $Script:Config.Enabled) {
            $result = 'Disabled'
            return $result
        }

        if (Test-WatchdogPaused) {
            $result = 'Paused'
            return $result
        }

        $sessionId = Get-CurrentSessionId
        if ($sessionId -le 0) {
            # Session 0 is the non-interactive services session; Dropbox cannot live there.
            $result = 'NonInteractiveSession'
            return $result
        }

        if (Test-DropboxRunning -SessionId $sessionId) {
            $state.ConsecutiveFailures = 0
            $result = 'Running'
            return $result
        }

        $target = Get-DropboxLaunchTarget
        if (-not $target) {
            $result = 'NotInstalled'
            return $result
        }

        if (Test-DropboxMaintenanceRunning -SessionId $sessionId) {
            $result = 'MaintenanceInProgress'
            return $result
        }

        if (-not (Test-SessionInteractive -SessionId $sessionId)) {
            $result = 'SessionNotReady'
            return $result
        }

        $recentRestarts = Get-RecentRestartCount -State $state -NowUtc $nowUtc
        if ($recentRestarts -ge [int]$Script:Config.MaxRestartsPerHour) {
            Write-WatchdogLog -Level 'Error' -EventId $Script:EventIds.CrashLoop -Message (
                'Dropbox has been restarted {0} times in the last hour and is down again. ' +
                'Suppressing further restarts until the hourly window clears so a broken client ' +
                'is not respawned in a loop. Investigate this device. Launch target: {1}' -f
                $recentRestarts, $target.Path)
            $result = 'Throttled'
            return $result
        }

        $backoff = Get-BackoffSeconds -ConsecutiveFailures ([int]$state.ConsecutiveFailures) `
            -BackoffSeconds $Script:Config.BackoffSeconds
        if ($backoff -gt 0) {
            Start-Sleep -Seconds $backoff
        }

        $evidence = Get-DropboxCrashEvidence
        $evidenceText = 'no crash record found in the Application log'
        if ($evidence) { $evidenceText = $evidence }

        Write-WatchdogLog -Level 'Warn' -EventId $Script:EventIds.RestartAttempt -Message (
            'Dropbox is not running in session {0}. Relaunching "{1}" {2} (discovered via {3}). Preceding event: {4}' -f
            $sessionId, $target.Path, (@($target.Arguments) -join ' '), $target.Source, $evidenceText)

        try {
            Start-DropboxProcess -Target $target
        } catch {
            $state.ConsecutiveFailures = [int]$state.ConsecutiveFailures + 1
            Write-WatchdogLog -Level 'Error' -EventId $Script:EventIds.RestartFailed -Message (
                'Failed to launch "{0}": {1}' -f $target.Path, $_.Exception.Message)
            $result = 'RestartFailed'
            return $result
        }

        Start-Sleep -Seconds ([int]$Script:Config.SettleSeconds)

        if (Test-DropboxRunning -SessionId $sessionId) {
            $state.ConsecutiveFailures = 0
            $state.LastRestartUtc = $nowUtc.ToString('o')
            $state.RestartHistoryUtc = @(@($state.RestartHistoryUtc) + $nowUtc.ToString('o'))
            Write-WatchdogLog -Level 'Info' -EventId $Script:EventIds.RestartSucceeded -Message (
                'Dropbox restarted successfully in session {0} and survived {1}s.' -f
                $sessionId, [int]$Script:Config.SettleSeconds)
            $result = 'Restarted'
            return $result
        }

        $state.ConsecutiveFailures = [int]$state.ConsecutiveFailures + 1
        $state.RestartHistoryUtc = @(@($state.RestartHistoryUtc) + $nowUtc.ToString('o'))
        Write-WatchdogLog -Level 'Error' -EventId $Script:EventIds.RestartFailed -Message (
            'Dropbox was launched from "{0}" but exited within {1}s (consecutive failures: {2}).' -f
            $target.Path, [int]$Script:Config.SettleSeconds, $state.ConsecutiveFailures)
        $result = 'RestartDidNotStick'
        return $result
    } catch {
        Write-WatchdogLog -Level 'Error' -EventId $Script:EventIds.WatchdogError -Message (
            'Unhandled error during watchdog cycle: {0}' -f $_.Exception.Message)
        $result = 'Error'
        return $result
    } finally {
        $state.LastResult = $result
        Save-WatchdogState -State $state | Out-Null
    }
}

function Test-WatchdogShouldContinue {
    <#
        The service loop exits (rather than lingering) when the desktop goes away or the
        deployed payload is replaced/removed, so the scheduled task can start the new one.
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not (Test-Path -LiteralPath $Script:Paths.PayloadPath)) { return $false }
    } catch {
        return $false
    }

    $current = Get-WatchdogConfig -ConfigPath $Script:Paths.ConfigPath
    if ([string]$current.PayloadVersion -ne [string]$Script:PayloadVersion) { return $false }
    if (-not $current.Enabled) { return $false }

    $sessionId = Get-CurrentSessionId
    if (-not (Test-SessionInteractive -SessionId $sessionId)) { return $false }

    return $true
}

function Get-WatchdogLockOwner {
    <#
        Returns the PID recorded in the lock file if that process is still a live
        PowerShell host, otherwise $null (stale lock, or no lock).
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not (Test-Path -LiteralPath $Script:Paths.LockPath)) { return $null }
        $recorded = (Get-Content -LiteralPath $Script:Paths.LockPath -Raw -ErrorAction Stop).Trim()
        if ([string]::IsNullOrWhiteSpace($recorded)) { return $null }
        $ownerPid = [int]$recorded
        if ($ownerPid -eq $PID) { return $null }

        $proc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
        if (-not $proc) { return $null }
        # Guard against PID reuse by a completely unrelated process.
        if ($proc.Name -notlike '*powershell*' -and $proc.Name -notlike '*pwsh*' -and $proc.Name -notlike '*conhost*') {
            return $null
        }
        return $ownerPid
    } catch {
        return $null
    }
}

function Set-WatchdogLock {
    [CmdletBinding()]
    param()
    try {
        if (-not (Test-Path -LiteralPath $Script:Paths.UserDir)) {
            New-Item -ItemType Directory -Path $Script:Paths.UserDir -Force | Out-Null
        }
        Set-Content -LiteralPath $Script:Paths.LockPath -Value ([string]$PID) -Encoding UTF8 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Remove-WatchdogLock {
    <# Only removes the lock if we still own it, so we never free someone else's. #>
    [CmdletBinding()]
    param()
    try {
        if (-not (Test-Path -LiteralPath $Script:Paths.LockPath)) { return $false }
        $recorded = (Get-Content -LiteralPath $Script:Paths.LockPath -Raw -ErrorAction Stop).Trim()
        if ($recorded -ne [string]$PID) { return $false }
        Remove-Item -LiteralPath $Script:Paths.LockPath -Force -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Invoke-WatchdogService {
    <#
        Long-running supervisor. Exactly one instance per user session, so the scheduled
        task's repeating trigger acts as a cheap resurrector for the loop itself without
        ever running two copies side by side.

        A PID lock file rather than a named mutex: New-Object System.Threading.Mutex is
        blocked under ConstrainedLanguage, and this runs as a standard user. The lock is
        per-user (it lives in %LOCALAPPDATA%), and a stale lock left by a killed process
        is reclaimed automatically because the recorded PID no longer resolves to a live
        PowerShell host. The residual race is a rare duplicate cycle, which is harmless:
        both instances would observe the same state and Dropbox single-instances itself.
    #>
    [CmdletBinding()]
    param()

    $owned = $false
    try {
        $existingOwner = Get-WatchdogLockOwner
        if ($existingOwner) {
            Write-WatchdogLog -Level 'Info' -Message (
                'Another watchdog instance (PID {0}) already owns this session; exiting.' -f $existingOwner)
            return 0
        }

        $owned = Set-WatchdogLock
        if (-not $owned) {
            Write-WatchdogLog -Level 'Warn' -Message 'Could not take the session lock; exiting rather than risk a duplicate loop.'
            return 0
        }

        Write-WatchdogLog -Level 'Info' -EventId $Script:EventIds.ServiceStarted -Message (
            'Watchdog {0} started in session {1} (poll every {2}s).' -f
            $Script:PayloadVersion, (Get-CurrentSessionId), [int]$Script:Config.PollSeconds)

        $deadline = (Get-Date).AddHours([double]$Script:Config.ServiceMaxHours)
        while ((Get-Date) -lt $deadline) {
            if (-not (Test-WatchdogShouldContinue)) { break }
            Invoke-WatchdogCycle | Out-Null
            Start-Sleep -Seconds ([int]$Script:Config.PollSeconds)
        }

        Write-WatchdogLog -Level 'Info' -EventId $Script:EventIds.ServiceStopped -Message `
            'Watchdog loop exiting; the scheduled task will start a fresh instance when required.'
        return 0
    } finally {
        if ($owned) {
            Remove-WatchdogLock | Out-Null
        }
    }
}

function Get-PowerShellLanguageMode {
    [CmdletBinding()]
    param()
    try {
        return [string]$ExecutionContext.SessionState.LanguageMode
    } catch {
        return 'Unknown'
    }
}

function Test-FullLanguageMode {
    [CmdletBinding()]
    param()
    $mode = Get-PowerShellLanguageMode
    return ($mode -eq 'FullLanguage' -or $mode -eq 'Unknown')
}

function Invoke-WatchdogMain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$Root
    )

    Initialize-Watchdog -Root $Root | Out-Null

    if ($Mode -eq 'Service') {
        return (Invoke-WatchdogService)
    }

    $result = Invoke-WatchdogCycle
    Write-WatchdogLog -Level 'Info' -Message ('Single-pass check result: {0}' -f $result)
    Write-Output $result
    return 0
}

# DBW_TEST_IMPORT lets the test suite dot-source this file for unit testing without
# executing the watchdog.
if (-not $env:DBW_TEST_IMPORT) {
    # No language-mode gate here on purpose. This script is written to run under
    # ConstrainedLanguage as well as FullLanguage - no [pscustomobject] casts, no
    # New-Object on non-core types, no static .NET calls on the hot paths. The mode is
    # recorded in the heartbeat so the SYSTEM-context detection script can report it.
    try {
        $exitCode = Invoke-WatchdogMain -Mode $Mode -Root $InstallRoot
        exit ([int]$exitCode)
    } catch {
        try {
            Write-WatchdogLog -Level 'Error' -EventId 4000 -Message ('Fatal: {0}' -f $_.Exception.Message)
        } catch { }
        Write-Error $_
        exit 1
    }
}
