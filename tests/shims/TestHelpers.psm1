<# Helpers shared by the Pester specs. #>
Set-StrictMode -Version 2.0

function New-TestSandbox {
    <# Creates an isolated fake %ProgramData% / %LOCALAPPDATA% pair for one test. #>
    [CmdletBinding()]
    param()
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-" + [Guid]::NewGuid().ToString('n'))
    $programData = Join-Path $root 'ProgramData'
    $localAppData = Join-Path $root 'LocalAppData'
    New-Item -ItemType Directory -Path $programData -Force | Out-Null
    New-Item -ItemType Directory -Path $localAppData -Force | Out-Null

    [pscustomobject]@{
        Root         = $root
        ProgramData  = $programData
        LocalAppData = $localAppData
    }
}

function Remove-TestSandbox {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Sandbox)
    if ($Sandbox -and (Test-Path -LiteralPath $Sandbox.Root)) {
        Remove-Item -LiteralPath $Sandbox.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function New-FakeProcess {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$SessionId, [string]$Name = 'Dropbox')
    [pscustomobject]@{ Name = $Name; SessionId = $SessionId; Id = Get-Random -Minimum 100 -Maximum 9999 }
}

function New-FakeTrigger {
    [CmdletBinding()]
    param([string]$CimClassName, [string]$Interval)
    $repetition = $null
    if ($Interval) { $repetition = [pscustomobject]@{ Interval = $Interval } }
    [pscustomobject]@{
        CimClass   = [pscustomobject]@{ CimClassName = $CimClassName }
        Repetition = $repetition
    }
}

function New-FakeScheduledTask {
    <# Builds a task object shaped like what Get-ScheduledTask returns. #>
    [CmdletBinding()]
    param(
        [string]$State = 'Ready',
        [string]$GroupId = 'S-1-5-32-545',
        [string]$Execute,
        [string]$Arguments,
        [object[]]$Triggers
    )
    if (-not $Triggers) {
        $Triggers = @(
            (New-FakeTrigger -CimClassName 'MSFT_TaskLogonTrigger'),
            (New-FakeTrigger -CimClassName 'MSFT_TaskTimeTrigger' -Interval 'PT30M')
        )
    }
    [pscustomobject]@{
        State     = $State
        Principal = [pscustomobject]@{ GroupId = $GroupId }
        Actions   = @([pscustomobject]@{ Execute = $Execute; Arguments = $Arguments })
        Triggers  = @($Triggers)
    }
}

Export-ModuleMember -Function New-TestSandbox, Remove-TestSandbox, New-FakeProcess,
    New-FakeTrigger, New-FakeScheduledTask
