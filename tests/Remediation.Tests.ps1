#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<# Unit tests for the built Intune remediation script. #>

BeforeAll {
    $env:DBW_TEST_IMPORT = '1'
    Import-Module "$PSScriptRoot/shims/WindowsShims.psm1" -Force -Global
    Import-Module "$PSScriptRoot/shims/TestHelpers.psm1" -Force -Global

    $Script:RepoRoot      = Split-Path -Parent $PSScriptRoot
    $Script:SourcePayload = Join-Path $Script:RepoRoot 'src/payload/DropboxWatchdog.ps1'
    $Script:RemediateScript = Join-Path $Script:RepoRoot 'build/Remediate-DropboxWatchdog.ps1'

    if (-not (Test-Path -LiteralPath $Script:RemediateScript)) {
        throw "build/Remediate-DropboxWatchdog.ps1 not found. Run scripts/build.sh first."
    }
    . $Script:RemediateScript
}

Describe 'Embedded payload' {
    It 'decompresses to exactly the source payload, byte for byte' {
        $expected = [System.IO.File]::ReadAllBytes($Script:SourcePayload)
        $actual   = Expand-PayloadBytes -Base64 $Script:PayloadGzipBase64
        $actual.Length | Should -Be $expected.Length
        [System.Convert]::ToBase64String($actual) | Should -Be ([System.Convert]::ToBase64String($expected))
    }

    It 'matches the SHA-256 the detection script will enforce' {
        $bytes = Expand-PayloadBytes -Base64 $Script:PayloadGzipBase64
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
        } finally {
            $sha.Dispose()
        }
        $hash | Should -Be (Get-WatchdogContract).PayloadSha256
    }
}

Describe 'Install-WatchdogPayload' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData = $Script:Sandbox.ProgramData
        $env:SystemRoot  = 'C:\Windows'
        $Script:Contract = Get-WatchdogContract
    }
    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'creates the install tree and writes a verified payload' {
        Install-WatchdogPayload -Contract $Script:Contract | Out-Null
        Test-Path -LiteralPath $Script:Contract.PayloadPath | Should -BeTrue
        (Get-FileHash -LiteralPath $Script:Contract.PayloadPath -Algorithm SHA256).Hash |
            Should -Be $Script:Contract.PayloadSha256
    }

    It 'is idempotent when run repeatedly' {
        Install-WatchdogPayload -Contract $Script:Contract | Out-Null
        $first = (Get-FileHash -LiteralPath $Script:Contract.PayloadPath -Algorithm SHA256).Hash
        Install-WatchdogPayload -Contract $Script:Contract | Out-Null
        (Get-FileHash -LiteralPath $Script:Contract.PayloadPath -Algorithm SHA256).Hash | Should -Be $first
    }

    It 'refuses to leave an unverified payload behind' {
        Mock Get-FileHash { return [pscustomobject]@{ Hash = 'DEADBEEF' } }
        { Install-WatchdogPayload -Contract $Script:Contract } | Should -Throw '*hash verification failed*'
    }

    It 'fails loudly if the embedded payload is empty' {
        Mock Expand-PayloadBytes { return [byte[]]@() }
        { Install-WatchdogPayload -Contract $Script:Contract } | Should -Throw '*zero bytes*'
    }
}

Describe 'Set-WatchdogAcl' {
    BeforeEach {
        $env:ProgramData = 'C:\ProgramData'
        $env:SystemRoot  = 'C:\Windows'
        $Script:Contract = Get-WatchdogContract
    }

    It 'grants Users read+execute only, by SID, and removes inheritance' {
        $Script:captured = $null
        Mock Invoke-Icacls {
            param($Arguments)
            $Script:captured = $Arguments
            return [pscustomobject]@{ ExitCode = 0; Output = '' }
        }
        Set-WatchdogAcl -Contract $Script:Contract | Should -BeTrue

        $joined = ($Script:captured -join ' ')
        $joined | Should -Match '/inheritance:r'
        $joined | Should -Match '\*S-1-5-18:\(OI\)\(CI\)F'
        $joined | Should -Match '\*S-1-5-32-544:\(OI\)\(CI\)F'
        $joined | Should -Match '\*S-1-5-32-545:\(OI\)\(CI\)RX'
        $joined | Should -Not -Match '\*S-1-5-32-545:\(OI\)\(CI\)(F|M)'
    }

    It 'throws when icacls fails, so remediation does not report a false success' {
        Mock Invoke-Icacls { return [pscustomobject]@{ ExitCode = 5; Output = 'Access is denied.' } }
        { Set-WatchdogAcl -Contract $Script:Contract } | Should -Throw '*icacls failed*'
    }
}

Describe 'Write-WatchdogConfig' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData = $Script:Sandbox.ProgramData
        $env:SystemRoot  = 'C:\Windows'
        $Script:Contract = Get-WatchdogContract
        New-Item -ItemType Directory -Path $Script:Contract.BinDir -Force | Out-Null
    }
    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'writes the version stamp the detection script compares against' {
        Write-WatchdogConfig -Contract $Script:Contract | Out-Null
        $config = Get-Content -LiteralPath $Script:Contract.ConfigPath -Raw | ConvertFrom-Json
        $config.PayloadVersion  | Should -Be $Script:Contract.PayloadVersion
        $config.ContractVersion | Should -Be $Script:Contract.ContractVersion
    }

    It 'writes the runtime tuning the payload reads' {
        Write-WatchdogConfig -Contract $Script:Contract | Out-Null
        $config = Get-Content -LiteralPath $Script:Contract.ConfigPath -Raw | ConvertFrom-Json
        $config.PollSeconds        | Should -Be 45
        $config.MaxRestartsPerHour | Should -Be 6
        $config.Enabled            | Should -BeTrue
        @($config.BackoffSeconds).Count | Should -BeGreaterThan 0
    }
}

Describe 'Register-WatchdogTask' {
    BeforeEach {
        $env:ProgramData = 'C:\ProgramData'
        $env:SystemRoot  = 'C:\Windows'
        $Script:Contract = Get-WatchdogContract

        $Script:action     = $null
        $Script:principal  = $null
        $Script:settings   = $null
        $Script:triggers   = @()
        $Script:registered = $null

        Mock Test-HeadlessConsoleSupported { return $true }
        Mock New-ScheduledTaskAction {
            param($Execute, $Argument)
            $Script:action = [pscustomobject]@{ Execute = $Execute; Arguments = $Argument }
            return $Script:action
        }
        Mock New-ScheduledTaskTrigger {
            param($AtLogOn, $Once, $At, $RepetitionInterval, $RepetitionDuration)
            $trigger = [pscustomobject]@{
                Kind = $(if ($AtLogOn) { 'Logon' } else { 'Once' })
                At = $At
                RepetitionInterval = $RepetitionInterval
                Delay = $null
            }
            $Script:triggers += $trigger
            return $trigger
        }
        Mock New-ScheduledTaskPrincipal {
            param($GroupId, $RunLevel)
            $Script:principal = [pscustomobject]@{ GroupId = $GroupId; RunLevel = $RunLevel }
            return $Script:principal
        }
        Mock New-ScheduledTaskSettingsSet {
            param($MultipleInstances, $ExecutionTimeLimit, $RestartCount, $Hidden, $StartWhenAvailable)
            $Script:settings = [pscustomobject]@{
                MultipleInstances = $MultipleInstances
                ExecutionTimeLimit = $ExecutionTimeLimit
                RestartCount = $RestartCount
                Hidden = [bool]$Hidden
                StartWhenAvailable = [bool]$StartWhenAvailable
            }
            return $Script:settings
        }
        Mock Register-ScheduledTask {
            param($TaskName, $TaskPath, $Action, $Trigger, $Principal, $Settings, $Description, $Force)
            $Script:registered = [pscustomobject]@{
                TaskName = $TaskName; TaskPath = $TaskPath; Triggers = @($Trigger); Force = [bool]$Force
            }
            return $Script:registered
        }
    }

    It 'scopes the task to the Users group with limited rights, not to a single user' {
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $Script:principal.RunLevel | Should -Be 'Limited'
        Test-GroupIdMatch -ActualGroupId $Script:principal.GroupId | Should -BeTrue
    }

    It 'runs the payload windowlessly in service mode via the 5.1 host' {
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $Script:action.Execute | Should -Be 'C:\Windows\System32\conhost.exe'
        $Script:action.Arguments | Should -Match '^--headless'
        $Script:action.Arguments | Should -Match 'WindowsPowerShell\\v1\.0\\powershell\.exe'
        $Script:action.Arguments | Should -Match '-Mode Service'
        $Script:action.Arguments | Should -Match '-NoProfile'
        $Script:action.Arguments | Should -Match '-ExecutionPolicy Bypass'
    }

    It 'falls back to launching powershell directly when conhost --headless is unusable' {
        Mock Test-HeadlessConsoleSupported { return $false }
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $Script:action.Execute | Should -Be $Script:Contract.TaskExecuteFallback
        $Script:action.Arguments | Should -Be $Script:Contract.TaskArgumentFallback
        $Script:action.Arguments | Should -Match '-WindowStyle Hidden'
        $Script:action.Arguments | Should -Match '-Mode Service'
    }

    It 'records which launcher it chose' {
        Mock Test-HeadlessConsoleSupported { return $true }
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $Script:SelectedLauncher | Should -Be 'headless'

        Mock Test-HeadlessConsoleSupported { return $false }
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $Script:SelectedLauncher | Should -Be 'direct'
    }

    It 'registers both a logon trigger and a repeating supervisor trigger' {
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        @($Script:triggers | Where-Object { $_.Kind -eq 'Logon' }).Count | Should -Be 1
        $once = @($Script:triggers | Where-Object { $_.Kind -eq 'Once' })
        $once.Count | Should -Be 1
        $once[0].RepetitionInterval | Should -Be (New-TimeSpan -Minutes $Script:Contract.SupervisorMinutes)
    }

    It 'delays the logon trigger so it does not fight the shell starting up' {
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $logon = @($Script:triggers | Where-Object { $_.Kind -eq 'Logon' })[0]
        $logon.Delay | Should -Be $Script:Contract.LogonDelay
    }

    It 'allows parallel instances so concurrent user sessions each get a watchdog' {
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $Script:settings.MultipleInstances | Should -Be 'Parallel'
        $Script:settings.ExecutionTimeLimit | Should -Be ([TimeSpan]::Zero)
        $Script:settings.Hidden | Should -BeTrue
        $Script:settings.StartWhenAvailable | Should -BeTrue
    }

    It 'overwrites any previous registration so drift is repaired' {
        Register-WatchdogTask -Contract $Script:Contract | Out-Null
        $Script:registered.Force | Should -BeTrue
        $Script:registered.TaskName | Should -Be 'DropboxWatchdog'
        $Script:registered.TaskPath | Should -Be '\DropboxWatchdog\'
    }
}

Describe 'Test-HeadlessConsoleSupported' {
    BeforeEach {
        $env:ProgramData = 'C:\ProgramData'
        $env:SystemRoot  = 'C:\Windows'
        $Script:Contract = Get-WatchdogContract
    }

    It 'reports unsupported when conhost.exe is not present' {
        Mock Test-Path { return $false }
        Test-HeadlessConsoleSupported -Contract $Script:Contract | Should -BeFalse
    }

    It 'reports supported when the probe process exits cleanly' {
        Mock Test-Path { return $true }
        Mock Start-Process {
            [pscustomobject]@{ ExitCode = 0 } |
                Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) $true } -PassThru
        }
        Test-HeadlessConsoleSupported -Contract $Script:Contract | Should -BeTrue
    }

    It 'reports unsupported when the probe exits non-zero' {
        Mock Test-Path { return $true }
        Mock Start-Process {
            [pscustomobject]@{ ExitCode = 1 } |
                Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) $true } -PassThru
        }
        Test-HeadlessConsoleSupported -Contract $Script:Contract | Should -BeFalse
    }

    It 'kills and reports unsupported when the probe hangs' {
        Mock Test-Path { return $true }
        $Script:killed = $false
        Mock Start-Process {
            [pscustomobject]@{ ExitCode = 0 } |
                Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) $false } -PassThru |
                Add-Member -MemberType ScriptMethod -Name Kill -Value { $Script:killed = $true } -PassThru
        }
        Test-HeadlessConsoleSupported -Contract $Script:Contract | Should -BeFalse
        $Script:killed | Should -BeTrue
    }
}

Describe 'Install-WatchdogTask' {
    BeforeEach {
        $env:ProgramData = 'C:\ProgramData'
        $env:SystemRoot  = 'C:\Windows'
        $Script:Contract = Get-WatchdogContract
        Mock Register-WatchdogTask { return $true }
    }

    It 'confirms the task exists after registering it' {
        Mock Get-WatchdogScheduledTask { return (New-FakeScheduledTask) }
        Install-WatchdogTask -Contract $Script:Contract | Should -BeTrue
    }

    It 'throws when registration silently produced nothing' {
        Mock Get-WatchdogScheduledTask { return $null }
        { Install-WatchdogTask -Contract $Script:Contract } | Should -Throw '*not present after registration*'
    }
}

Describe 'Invoke-Remediation' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData = $Script:Sandbox.ProgramData
        $env:SystemRoot  = 'C:\Windows'
        Mock Invoke-Icacls { return [pscustomobject]@{ ExitCode = 0; Output = '' } }
        Mock Register-EventSource { return $true }
        Mock Register-WatchdogTask { return $true }
        Mock Get-WatchdogScheduledTask { return (New-FakeScheduledTask) }
    }
    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'installs everything and reports success' {
        $result = Invoke-Remediation
        $result.ExitCode | Should -Be 0
        $result.Message | Should -Match '^REMEDIATED'
        $result.Message.Length | Should -BeLessOrEqual 2048

        $contract = Get-WatchdogContract
        Test-Path -LiteralPath $contract.PayloadPath | Should -BeTrue
        Test-Path -LiteralPath $contract.ConfigPath  | Should -BeTrue
    }

    It 'propagates a hard failure instead of exiting 0' {
        Mock Invoke-Icacls { return [pscustomobject]@{ ExitCode = 5; Output = 'denied' } }
        { Invoke-Remediation } | Should -Throw '*icacls failed*'
    }

    It 'refuses to install under ConstrainedLanguage rather than half-installing' {
        Mock Test-FullLanguageMode { return $false }
        Mock Get-PowerShellLanguageMode { return 'ConstrainedLanguage' }
        { Invoke-Remediation } | Should -Throw '*ConstrainedLanguage*'

        # Nothing should have been written: a partial install would look like a stale
        # heartbeat an hour later instead of naming its own cause.
        $contract = Get-WatchdogContract
        Test-Path -LiteralPath $contract.PayloadPath | Should -BeFalse
    }

    It 'treats a missing event log source as non-fatal' {
        Mock Register-EventSource { throw 'access denied' }
        (Invoke-Remediation).ExitCode | Should -Be 0
    }
}
