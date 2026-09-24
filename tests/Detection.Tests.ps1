#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<# Unit tests for the built Intune detection script. #>

BeforeAll {
    $env:DBW_TEST_IMPORT = '1'
    Import-Module "$PSScriptRoot/shims/WindowsShims.psm1" -Force -Global
    Import-Module "$PSScriptRoot/shims/TestHelpers.psm1" -Force -Global

    $Script:RepoRoot    = Split-Path -Parent $PSScriptRoot
    $Script:SourcePayload = Join-Path $Script:RepoRoot 'src/payload/DropboxWatchdog.ps1'
    $Script:DetectScript  = Join-Path $Script:RepoRoot 'build/Detect-DropboxWatchdog.ps1'

    if (-not (Test-Path -LiteralPath $Script:DetectScript)) {
        throw "build/Detect-DropboxWatchdog.ps1 not found. Run scripts/build.sh first."
    }
    . $Script:DetectScript
}

Describe 'Detection' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData = $Script:Sandbox.ProgramData
        $env:SystemRoot  = 'C:\Windows'

        $Script:Contract = Get-WatchdogContract

        # Lay down a correctly installed watchdog.
        New-Item -ItemType Directory -Path $Script:Contract.BinDir -Force | Out-Null
        Copy-Item -LiteralPath $Script:SourcePayload -Destination $Script:Contract.PayloadPath -Force
        $config = @{
            PayloadVersion  = $Script:Contract.PayloadVersion
            ContractVersion = $Script:Contract.ContractVersion
        }
        Set-Content -LiteralPath $Script:Contract.ConfigPath -Value ($config | ConvertTo-Json)

        Mock Get-WatchdogScheduledTask {
            New-FakeScheduledTask -Execute $Script:Contract.TaskExecute -Arguments $Script:Contract.TaskArgument
        }
        Mock Get-InteractiveUserProfile { return @() }
    }

    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    Context 'healthy device' {
        It 'reports compliant and exits 0' {
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 0
            $result.Message | Should -Match '^COMPLIANT'
        }
    }

    Context 'payload problems' {
        It 'is non-compliant when the payload has never been installed' {
            Remove-Item -LiteralPath $Script:Contract.PayloadPath -Force
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'payload missing'
        }

        It 'is non-compliant when the payload has been tampered with' {
            Add-Content -LiteralPath $Script:Contract.PayloadPath -Value '# malicious edit'
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'payload hash mismatch'
        }

        It 'is non-compliant when an older payload version is installed' {
            Set-Content -LiteralPath $Script:Contract.ConfigPath `
                -Value (@{ PayloadVersion = '0.0.1'; ContractVersion = '1' } | ConvertTo-Json)
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'payload version 0\.0\.1 installed'
        }

        It 'is non-compliant when the runtime config is missing' {
            Remove-Item -LiteralPath $Script:Contract.ConfigPath -Force
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'runtime config missing'
        }
    }

    Context 'scheduled task problems' {
        It 'is non-compliant when the task is gone' {
            Mock Get-WatchdogScheduledTask { return $null }
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'scheduled task missing'
        }

        It 'is non-compliant when the task has been disabled' {
            Mock Get-WatchdogScheduledTask {
                New-FakeScheduledTask -State 'Disabled' `
                    -Execute $Script:Contract.TaskExecute -Arguments $Script:Contract.TaskArgument
            }
            (Invoke-Detection).Message | Should -Match 'scheduled task disabled'
        }

        It 'is non-compliant when the task is scoped to one user instead of the Users group' {
            Mock Get-WatchdogScheduledTask {
                New-FakeScheduledTask -GroupId 'CONTOSO\alice' `
                    -Execute $Script:Contract.TaskExecute -Arguments $Script:Contract.TaskArgument
            }
            (Invoke-Detection).Message | Should -Match 'expected the Users group'
        }

        It 'accepts the Users group by SID, by BUILTIN name and by bare name' {
            # SID translation is a Windows API; pin it so the locale-independent
            # matching logic is what is under test.
            Mock Get-UsersGroupName { return 'BUILTIN\Users' }
            foreach ($groupId in @('S-1-5-32-545', 'BUILTIN\Users', 'Users', 'builtin\users')) {
                Test-GroupIdMatch -ActualGroupId $groupId | Should -BeTrue
            }
            Test-GroupIdMatch -ActualGroupId 'CONTOSO\alice' | Should -BeFalse
            Test-GroupIdMatch -ActualGroupId $null | Should -BeFalse
        }

        It 'accepts the direct-powershell fallback launcher' {
            Mock Get-WatchdogScheduledTask {
                New-FakeScheduledTask -Execute $Script:Contract.TaskExecuteFallback `
                    -Arguments $Script:Contract.TaskArgumentFallback
            }
            (Invoke-Detection).ExitCode | Should -Be 0
        }

        It 'is non-compliant when the task action points somewhere else' {
            Mock Get-WatchdogScheduledTask {
                New-FakeScheduledTask -Execute 'C:\Windows\System32\calc.exe' -Arguments 'nope'
            }
            (Invoke-Detection).Message | Should -Match 'task action does not match'
        }

        It 'is non-compliant when the logon trigger has been removed' {
            Mock Get-WatchdogScheduledTask {
                New-FakeScheduledTask -Execute $Script:Contract.TaskExecute -Arguments $Script:Contract.TaskArgument `
                    -Triggers @((New-FakeTrigger -CimClassName 'MSFT_TaskTimeTrigger' -Interval 'PT30M'))
            }
            (Invoke-Detection).Message | Should -Match 'no logon trigger'
        }

        It 'is non-compliant when the repeating supervisor trigger has been removed' {
            Mock Get-WatchdogScheduledTask {
                New-FakeScheduledTask -Execute $Script:Contract.TaskExecute -Arguments $Script:Contract.TaskArgument `
                    -Triggers @((New-FakeTrigger -CimClassName 'MSFT_TaskLogonTrigger'))
            }
            (Invoke-Detection).Message | Should -Match 'no repeating supervisor trigger'
        }
    }

    Context 'heartbeat checks' {
        BeforeEach {
            $Script:ProfileDir = Join-Path $Script:Sandbox.Root 'Users/alice'
            New-Item -ItemType Directory -Path (Join-Path $Script:ProfileDir 'AppData/Local/DropboxWatchdog') -Force | Out-Null
            $Script:StatePath = Join-Path $Script:ProfileDir 'AppData/Local/DropboxWatchdog/state.json'
        }

        It 'is compliant when an established session has a fresh heartbeat' {
            Set-Content -LiteralPath $Script:StatePath `
                -Value (@{ LastCheckUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json)
            Mock Get-InteractiveUserProfile {
                @([pscustomobject]@{
                    Sid = 'S-1-5-21-1'; ProfilePath = $Script:ProfileDir
                    SessionStartUtc = [datetime]::UtcNow.AddHours(-2)
                })
            }
            (Invoke-Detection).ExitCode | Should -Be 0
        }

        It 'is non-compliant when a session watchdog has stopped reporting' {
            Set-Content -LiteralPath $Script:StatePath `
                -Value (@{ LastCheckUtc = [datetime]::UtcNow.AddHours(-4).ToString('o') } | ConvertTo-Json)
            Mock Get-InteractiveUserProfile {
                @([pscustomobject]@{
                    Sid = 'S-1-5-21-1'; ProfilePath = $Script:ProfileDir
                    SessionStartUtc = [datetime]::UtcNow.AddHours(-5)
                })
            }
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'heartbeat for SID S-1-5-21-1 is \d+ min old'
        }

        It 'is non-compliant when an established session has never produced a heartbeat' {
            Mock Get-InteractiveUserProfile {
                @([pscustomobject]@{
                    Sid = 'S-1-5-21-2'; ProfilePath = (Join-Path $Script:Sandbox.Root 'Users/bob')
                    SessionStartUtc = [datetime]::UtcNow.AddHours(-3)
                })
            }
            (Invoke-Detection).Message | Should -Match 'no watchdog heartbeat for SID S-1-5-21-2'
        }

        It 'gives a freshly logged-on session time before demanding a heartbeat' {
            Mock Get-InteractiveUserProfile {
                @([pscustomobject]@{
                    Sid = 'S-1-5-21-3'; ProfilePath = (Join-Path $Script:Sandbox.Root 'Users/carol')
                    SessionStartUtc = [datetime]::UtcNow.AddMinutes(-2)
                })
            }
            (Invoke-Detection).ExitCode | Should -Be 0
        }

        It 'evaluates every interactive session, not just the first' {
            Set-Content -LiteralPath $Script:StatePath `
                -Value (@{ LastCheckUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json)
            Mock Get-InteractiveUserProfile {
                @(
                    [pscustomobject]@{ Sid = 'S-1-5-21-1'; ProfilePath = $Script:ProfileDir; SessionStartUtc = [datetime]::UtcNow.AddHours(-2) },
                    [pscustomobject]@{ Sid = 'S-1-5-21-9'; ProfilePath = (Join-Path $Script:Sandbox.Root 'Users/dave'); SessionStartUtc = [datetime]::UtcNow.AddHours(-2) }
                )
            }
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'S-1-5-21-9'
        }
    }

    Context 'constrained language mode' {
        It 'reports the real cause instead of a confusing downstream failure' {
            Mock Test-FullLanguageMode { return $false }
            Mock Get-PowerShellLanguageMode { return 'ConstrainedLanguage' }
            $result = Invoke-Detection
            $result.ExitCode | Should -Be 1
            $result.Message | Should -Match 'ConstrainedLanguage'
            $result.Message | Should -Match 'AppLocker or WDAC'
            $result.Message | Should -Match 'Allow-list'
        }

        It 'does not block when the language mode cannot be determined' {
            Mock Get-PowerShellLanguageMode { return 'Unknown' }
            Test-FullLanguageMode | Should -BeTrue
        }

        It 'surfaces a constrained user session in the portal without failing the device' {
            $profileDir = Join-Path $Script:Sandbox.Root 'Users/frank'
            New-Item -ItemType Directory -Path (Join-Path $profileDir 'AppData/Local/DropboxWatchdog') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $profileDir 'AppData/Local/DropboxWatchdog/state.json') `
                -Value (@{ LastCheckUtc = [datetime]::UtcNow.ToString('o'); LanguageMode = 'ConstrainedLanguage' } | ConvertTo-Json)
            Mock Get-InteractiveUserProfile {
                @([pscustomobject]@{ Sid = 'S-1-5-21-42'; ProfilePath = $profileDir; SessionStartUtc = [datetime]::UtcNow.AddHours(-2) })
            }

            $result = Invoke-Detection
            $result.ExitCode | Should -Be 0 -Because 'the watchdog supports constrained mode, so this is a note, not a fault'
            $result.Message | Should -Match 'ConstrainedLanguage'
            $result.Message | Should -Match 'S-1-5-21-42'
        }

        It 'adds no note when every session is running FullLanguage' {
            $profileDir = Join-Path $Script:Sandbox.Root 'Users/grace'
            New-Item -ItemType Directory -Path (Join-Path $profileDir 'AppData/Local/DropboxWatchdog') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $profileDir 'AppData/Local/DropboxWatchdog/state.json') `
                -Value (@{ LastCheckUtc = [datetime]::UtcNow.ToString('o'); LanguageMode = 'FullLanguage' } | ConvertTo-Json)
            Mock Get-InteractiveUserProfile {
                @([pscustomobject]@{ Sid = 'S-1-5-21-43'; ProfilePath = $profileDir; SessionStartUtc = [datetime]::UtcNow.AddHours(-2) })
            }
            (Invoke-Detection).Message | Should -Not -Match 'restricted PowerShell'
        }
    }

    Context 'output constraints' {
        It 'keeps output within the Intune 2048 character limit' {
            Mock Get-InteractiveUserProfile {
                1..200 | ForEach-Object {
                    [pscustomobject]@{
                        Sid = "S-1-5-21-$_"
                        ProfilePath = "C:\Users\user$_"
                        SessionStartUtc = [datetime]::UtcNow.AddHours(-3)
                    }
                }
            }
            $result = Invoke-Detection
            $result.Message.Length | Should -BeLessOrEqual 2048
            $result.ExitCode | Should -Be 1
        }
    }
}

Describe 'Get-InteractiveUserProfile' {
    It 'maps explorer.exe owners to profile directories and de-duplicates sessions' {
        $proc = [pscustomobject]@{ Name = 'explorer.exe'; CreationDate = [datetime]::UtcNow.AddHours(-1) }
        Mock Get-CimInstance { return @($proc, $proc) }
        Mock Invoke-CimMethod { return [pscustomobject]@{ Sid = 'S-1-5-21-77' } }
        Mock Test-Path { return $true }
        Mock Get-ItemProperty { return [pscustomobject]@{ ProfileImagePath = 'C:\Users\erin' } }

        $profiles = @(Get-InteractiveUserProfile)
        $profiles.Count | Should -Be 1
        $profiles[0].Sid | Should -Be 'S-1-5-21-77'
        $profiles[0].ProfilePath | Should -Be 'C:\Users\erin'
    }

    It 'returns an empty set rather than throwing when WMI is unavailable' {
        Mock Get-CimInstance { throw 'RPC server unavailable' }
        @(Get-InteractiveUserProfile).Count | Should -Be 0
    }
}
