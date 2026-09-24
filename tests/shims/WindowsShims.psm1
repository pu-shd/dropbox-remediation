<#
    Stand-ins for Windows-only cmdlets so the scripts under test can be loaded and
    mocked on Linux/macOS PowerShell 7 inside the test container.

    Every shim THROWS when it is actually invoked. That is deliberate: if a test
    forgets to mock one of these, the test fails loudly instead of silently
    exercising a no-op. Silence must never look like success.
#>

Set-StrictMode -Version 2.0

function Script:Unmocked {
    param([string]$Name)
    throw "WindowsShims: '$Name' was called without a mock. Add an explicit Mock for it in the test."
}

function Get-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath, [switch]$ErrorAction)
    Script:Unmocked 'Get-ScheduledTask'
}

function Register-ScheduledTask {
    [CmdletBinding()]
    param(
        [string]$TaskName, [string]$TaskPath, $Action, $Trigger, $Principal, $Settings,
        [string]$Description, [switch]$Force
    )
    Script:Unmocked 'Register-ScheduledTask'
}

function Unregister-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath, [switch]$Confirm)
    Script:Unmocked 'Unregister-ScheduledTask'
}

function New-ScheduledTaskAction {
    [CmdletBinding()]
    param([string]$Execute, [string]$Argument)
    Script:Unmocked 'New-ScheduledTaskAction'
}

function New-ScheduledTaskTrigger {
    [CmdletBinding()]
    param([switch]$AtLogOn, [switch]$Once, $At, $RepetitionInterval, $RepetitionDuration)
    Script:Unmocked 'New-ScheduledTaskTrigger'
}

function New-ScheduledTaskPrincipal {
    [CmdletBinding()]
    param([string]$GroupId, [string]$RunLevel)
    Script:Unmocked 'New-ScheduledTaskPrincipal'
}

function New-ScheduledTaskSettingsSet {
    [CmdletBinding()]
    param(
        [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries,
        [switch]$StartWhenAvailable, [switch]$Hidden, [string]$MultipleInstances,
        $ExecutionTimeLimit, [int]$RestartCount, $RestartInterval
    )
    Script:Unmocked 'New-ScheduledTaskSettingsSet'
}

function Get-CimInstance {
    [CmdletBinding()]
    param([string]$ClassName, [string]$Filter)
    Script:Unmocked 'Get-CimInstance'
}

function Invoke-CimMethod {
    [CmdletBinding()]
    param($InputObject, [string]$MethodName)
    Script:Unmocked 'Invoke-CimMethod'
}

function Get-WinEvent {
    [CmdletBinding()]
    param($FilterHashtable, [int]$MaxEvents)
    Script:Unmocked 'Get-WinEvent'
}

function Get-AppxPackage {
    [CmdletBinding()]
    param([string]$Name)
    Script:Unmocked 'Get-AppxPackage'
}

Export-ModuleMember -Function `
    Get-ScheduledTask, Register-ScheduledTask, Unregister-ScheduledTask,
    New-ScheduledTaskAction, New-ScheduledTaskTrigger, New-ScheduledTaskPrincipal,
    New-ScheduledTaskSettingsSet, Get-CimInstance, Invoke-CimMethod, Get-WinEvent,
    Get-AppxPackage
