#region SHARED-CONTRACT
# ---------------------------------------------------------------------------------
# GENERATED BLOCK - do not edit inside build/ output.
# Source of truth: src/common/SharedContract.ps1
# Injected verbatim into the detection, remediation and uninstall scripts so all
# three agree byte-for-byte on paths, task shape and expected payload version.
# ---------------------------------------------------------------------------------
function Get-WatchdogContract {
    [CmdletBinding()]
    param()

    $programData = $env:ProgramData
    if ([string]::IsNullOrWhiteSpace($programData)) { $programData = 'C:\ProgramData' }
    $systemRoot = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { $systemRoot = 'C:\Windows' }

    $root        = "$programData\DropboxWatchdog"
    $payloadPath = "$root\bin\DropboxWatchdog.ps1"
    $powershell  = "$systemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $conhost     = "$systemRoot\System32\conhost.exe"

    # conhost --headless keeps the 5.1 host completely windowless, so users never see a
    # console flash when the task starts or when the supervisor trigger fires every
    # 30 minutes. If a device's conhost does not support --headless, the remediation
    # falls back to launching powershell.exe directly (which flashes briefly) rather
    # than registering a task that would never run.
    $psArgument   = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Mode Service' -f $payloadPath
    $taskArgument = '--headless "{0}" {1}' -f $powershell, $psArgument

    [pscustomobject]@{
        ContractVersion    = '1'
        ProductName        = 'DropboxWatchdog'
        InstallRoot        = $root
        BinDir             = "$root\bin"
        PayloadPath        = $payloadPath
        ConfigPath         = "$root\bin\version.json"
        MachinePauseMarker = "$root\pause.marker"
        TaskName           = 'DropboxWatchdog'
        TaskPath           = '\DropboxWatchdog\'
        EventLogName       = 'Application'
        EventSource        = 'DropboxWatchdog'
        UsersGroupSid      = 'S-1-5-32-545'
        TaskExecute        = $conhost
        TaskArgument       = $taskArgument
        TaskExecuteFallback  = $powershell
        TaskArgumentFallback = $psArgument
        PayloadVersion     = '@@PAYLOAD_VERSION@@'
        PayloadSha256      = '@@PAYLOAD_SHA256@@'
        SupervisorMinutes  = 30
        LogonDelay         = 'PT30S'
        # Written to ConfigPath and consumed by the payload at runtime.
        RuntimeConfig      = [ordered]@{
            Enabled               = $true
            PollSeconds           = 45
            SettleSeconds         = 20
            HeartbeatStaleMinutes = 90
            MaxRestartsPerHour    = 6
            BackoffSeconds        = @(5, 15, 60, 300, 900)
            MaxLogBytes           = 1048576
            ServiceMaxHours       = 24
        }
    }
}

function Get-ExpectedTaskAction {
    <#
        Both launcher variants the remediation is allowed to register. Detection accepts
        either, so a device that fell back to the direct launcher is not flagged
        non-compliant forever.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Contract)

    @(
        [pscustomobject]@{ Name = 'headless'; Execute = $Contract.TaskExecute;         Argument = $Contract.TaskArgument },
        [pscustomobject]@{ Name = 'direct';   Execute = $Contract.TaskExecuteFallback; Argument = $Contract.TaskArgumentFallback }
    )
}

function Get-PowerShellLanguageMode {
    <#
        AppLocker script enforcement and WDAC put PowerShell into ConstrainedLanguage,
        where New-Object, static .NET calls and typed collections all fail. Every script
        in this package needs FullLanguage, so report the mode plainly rather than
        letting the first blocked call surface as an unrelated-looking error.
    #>
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
    # 'Unknown' means we could not determine it; do not block on that.
    return ($mode -eq 'FullLanguage' -or $mode -eq 'Unknown')
}

function Get-LanguageModeMessage {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Contract)
    return ('PowerShell is running in {0}, not FullLanguage, in the SYSTEM context. AppLocker or WDAC script enforcement is active. The Intune Management Extension script directory and "{1}" both need allow-listing. (The watchdog itself runs fine constrained; it is this installer that cannot, because it must decompress an embedded payload.)' -f
        (Get-PowerShellLanguageMode), $Contract.BinDir)
}

function Get-UsersGroupName {
    <# Language-independent BUILTIN\Users resolution; falls back to the raw SID. #>
    [CmdletBinding()]
    param([string]$Sid = 'S-1-5-32-545')
    try {
        return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate(
            [System.Security.Principal.NTAccount]).Value
    } catch {
        return $Sid
    }
}

function Test-GroupIdMatch {
    <#
        Task Scheduler may hand back "S-1-5-32-545", "BUILTIN\Users" or "Users"
        depending on OS build and locale. Treat all three as the same principal.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][string]$ActualGroupId,
        [string]$ExpectedSid = 'S-1-5-32-545'
    )
    if ([string]::IsNullOrWhiteSpace($ActualGroupId)) { return $false }

    $accepted = New-Object System.Collections.Generic.List[string]
    $accepted.Add($ExpectedSid)
    $resolved = Get-UsersGroupName -Sid $ExpectedSid
    $accepted.Add($resolved)
    if ($resolved.Contains('\')) { $accepted.Add($resolved.Split('\')[-1]) }

    foreach ($candidate in $accepted) {
        if ($ActualGroupId.Trim() -eq $candidate) { return $true }
    }
    return $false
}
#endregion SHARED-CONTRACT
