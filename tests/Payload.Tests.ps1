#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Unit tests for the per-user watchdog payload.

    Windows-only surface (processes, registry, event log, Task Scheduler) is reached
    only through thin wrapper functions in the payload, so these tests mock the
    wrappers and exercise the real decision logic. Filesystem behaviour uses a real
    temp sandbox rather than a mocked Test-Path, so path handling is genuinely covered.
#>

BeforeAll {
    $env:DBW_TEST_IMPORT = '1'
    Import-Module "$PSScriptRoot/shims/WindowsShims.psm1" -Force -Global
    Import-Module "$PSScriptRoot/shims/TestHelpers.psm1" -Force -Global

    $Script:PayloadFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/payload/DropboxWatchdog.ps1'
    . $Script:PayloadFile
}

Describe 'Split-CommandLine' {
    It 'splits a quoted executable path from its arguments' {
        $tokens = Split-CommandLine -CommandLine '"C:\Users\ab\AppData\Local\Dropbox\bin\Dropbox.exe" /systemstartup'
        $tokens.Count | Should -Be 2
        $tokens[0] | Should -Be 'C:\Users\ab\AppData\Local\Dropbox\bin\Dropbox.exe'
        $tokens[1] | Should -Be '/systemstartup'
    }

    It 'keeps spaces inside quoted segments' {
        $tokens = Split-CommandLine -CommandLine '"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe" /a /b'
        $tokens[0] | Should -Be 'C:\Program Files (x86)\Dropbox\Client\Dropbox.exe'
        $tokens.Count | Should -Be 3
    }

    It 'returns an empty array for an empty command line' {
        @(Split-CommandLine -CommandLine '').Count | Should -Be 0
    }
}

Describe 'ConvertFrom-DropboxCommandLine' {
    It 'preserves the arguments Dropbox registered for itself' {
        $target = ConvertFrom-DropboxCommandLine -CommandLine '"C:\dbx\Dropbox.exe" /systemstartup /foo' -Source 'test'
        $target.Path | Should -Be 'C:\dbx\Dropbox.exe'
        (@($target.Arguments) -join ' ') | Should -Be '/systemstartup /foo'
    }

    It 'falls back to /systemstartup when the registered command has no arguments' {
        $target = ConvertFrom-DropboxCommandLine -CommandLine '"C:\dbx\Dropbox.exe"' -Source 'test'
        (@($target.Arguments) -join ' ') | Should -Be '/systemstartup'
    }

    It 'returns null for a blank command line' {
        ConvertFrom-DropboxCommandLine -CommandLine '   ' -Source 'test' | Should -BeNullOrEmpty
    }
}

Describe 'Dropbox discovery' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:LOCALAPPDATA = $Script:Sandbox.LocalAppData
        Mock Get-RegistryValue { return $null }
        # Candidate paths are Windows-shaped (backslashes, C:\...), so their existence
        # has to be mocked rather than staged on a Linux filesystem.
        Mock Test-Path { return $false }
    }

    AfterEach {
        Remove-TestSandbox -Sandbox $Script:Sandbox
    }

    It 'prefers the HKCU Run entry, because that is how Dropbox actually starts itself' {
        Mock Get-RegistryValue {
            param($Path, $Name)
            if ($Path -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -and $Name -eq 'Dropbox') {
                return '"C:\custom\Dropbox.exe" /systemstartup'
            }
            return $null
        }
        $candidates = @(Get-DropboxCandidate)
        $candidates[0].Path | Should -Be 'C:\custom\Dropbox.exe'
        $candidates[0].Source | Should -Be 'HKCU:Run'
    }

    It 'includes the per-user bin path that a SYSTEM-context script would never see' {
        $candidates = @(Get-DropboxCandidate)
        $paths = @($candidates | ForEach-Object { $_.Path })
        $paths | Should -Contain "$env:LOCALAPPDATA\Dropbox\bin\Dropbox.exe"
    }

    It 'includes machine-wide install locations' {
        $env:ProgramFiles = 'C:\Program Files'
        ${env:ProgramFiles(x86)} = 'C:\Program Files (x86)'
        $paths = @(Get-DropboxCandidate | ForEach-Object { $_.Path })
        $paths | Should -Contain 'C:\Program Files (x86)\Dropbox\Client\Dropbox.exe'
        $paths | Should -Contain 'C:\Program Files\Dropbox\Client\Dropbox.exe'
    }

    It 'expands InstallLocation from an uninstall key into the known client layouts' {
        Mock Get-RegistryValue {
            param($Path, $Name)
            if ($Path -like '*Uninstall\Dropbox' -and $Name -eq 'InstallLocation') { return 'C:\dbx\' }
            return $null
        }
        $paths = @(Get-DropboxCandidate | ForEach-Object { $_.Path })
        $paths | Should -Contain 'C:\dbx\Client\Dropbox.exe'
        $paths | Should -Contain 'C:\dbx\bin\Dropbox.exe'
    }

    It 'resolves to the first candidate that exists on disk' {
        $expected = "$env:LOCALAPPDATA\Dropbox\bin\Dropbox.exe"
        Mock Test-Path {
            param($LiteralPath)
            return ($LiteralPath -eq $expected)
        }

        Mock Get-RegistryValue {
            param($Path, $Name)
            # A stale Run entry pointing at a removed install must not win.
            if ($Path -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -and $Name -eq 'Dropbox') {
                return '"C:\gone\Dropbox.exe" /systemstartup'
            }
            return $null
        }
        Mock Get-DropboxAppxTarget { return $null }

        $target = Get-DropboxLaunchTarget
        $target | Should -Not -BeNullOrEmpty
        $target.Path | Should -Be "$env:LOCALAPPDATA\Dropbox\bin\Dropbox.exe"
    }

    It 'falls back to the Microsoft Store package when no classic executable exists' {
        Mock Get-DropboxAppxTarget {
            return [pscustomobject]@{ Path = 'C:\Windows\explorer.exe'; Arguments = @('shell:AppsFolder\X!Dropbox'); Source = 'AppxPackage' }
        }
        $target = Get-DropboxLaunchTarget
        $target.Source | Should -Be 'AppxPackage'
    }

    It 'returns null when Dropbox is installed nowhere' {
        Mock Get-DropboxAppxTarget { return $null }
        Get-DropboxLaunchTarget | Should -BeNullOrEmpty
    }
}

Describe 'Session-scoped process checks' {
    It 'reports Dropbox running only for the calling session' {
        Mock Get-ProcessByName { return @((New-FakeProcess -SessionId 2)) }
        Test-DropboxRunning -SessionId 2 | Should -BeTrue
        Test-DropboxRunning -SessionId 3 | Should -BeFalse
    }

    It 'treats another user session as not running, so we never touch their client' {
        Mock Get-ProcessByName { return @((New-FakeProcess -SessionId 7)) }
        Test-DropboxRunning -SessionId 1 | Should -BeFalse
    }

    It 'detects an in-session Dropbox updater' {
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'DropboxUpdate') { return @((New-FakeProcess -SessionId 1 -Name 'DropboxUpdate')) }
            return @()
        }
        Test-DropboxMaintenanceRunning -SessionId 1 | Should -BeTrue
        Test-DropboxMaintenanceRunning -SessionId 4 | Should -BeFalse
    }

    It 'requires explorer in the same session before calling the desktop ready' {
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            return @()
        }
        Test-SessionInteractive -SessionId 1 | Should -BeTrue
        Test-SessionInteractive -SessionId 2 | Should -BeFalse
        Test-SessionInteractive -SessionId 0 | Should -BeFalse
    }
}

Describe 'Crash-loop accounting' {
    It 'walks the backoff ladder and holds at its last rung' {
        $ladder = @(5, 15, 60)
        Get-BackoffSeconds -ConsecutiveFailures 0 -BackoffSeconds $ladder | Should -Be 0
        Get-BackoffSeconds -ConsecutiveFailures 1 -BackoffSeconds $ladder | Should -Be 5
        Get-BackoffSeconds -ConsecutiveFailures 2 -BackoffSeconds $ladder | Should -Be 15
        Get-BackoffSeconds -ConsecutiveFailures 3 -BackoffSeconds $ladder | Should -Be 60
        Get-BackoffSeconds -ConsecutiveFailures 99 -BackoffSeconds $ladder | Should -Be 60
    }

    It 'counts only restarts inside the rolling window and prunes the rest' {
        $now = [datetime]::UtcNow
        $state = [pscustomobject]@{
            RestartHistoryUtc = @(
                $now.AddMinutes(-5).ToString('o'),
                $now.AddMinutes(-30).ToString('o'),
                $now.AddMinutes(-90).ToString('o'),
                'not-a-timestamp'
            )
        }
        Get-RecentRestartCount -State $state -NowUtc $now | Should -Be 2
        @($state.RestartHistoryUtc).Count | Should -Be 2
    }
}

Describe 'Invoke-WatchdogCycle' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData  = $Script:Sandbox.ProgramData
        $env:LOCALAPPDATA = $Script:Sandbox.LocalAppData

        $Script:Root = Join-Path $Script:Sandbox.ProgramData 'DropboxWatchdog'
        New-Item -ItemType Directory -Path (Join-Path $Script:Root 'bin') -Force | Out-Null

        # Discovery is covered by its own Describe; here we pin a known target so the
        # cycle's decision logic is what is under test.
        $Script:Target = [pscustomobject]@{
            Path      = 'C:\Users\alice\AppData\Local\Dropbox\bin\Dropbox.exe'
            Arguments = @('/systemstartup')
            Source    = 'LocalAppData\bin'
        }
        Mock Get-DropboxLaunchTarget { return $Script:Target }
        Mock Get-RegistryValue { return $null }
        Mock Get-DropboxAppxTarget { return $null }
        Mock Write-WatchdogEvent { return $true }
        Mock Get-DropboxCrashEvidence { return 'Application Error/1000: Dropbox.exe faulting module ntdll.dll' }
        Mock Start-Sleep { }
        Mock Start-DropboxProcess { }
        Mock Get-CurrentSessionId { return 1 }
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            return @()
        }

        Initialize-Watchdog -Root $Script:Root | Out-Null
    }

    AfterEach {
        Remove-TestSandbox -Sandbox $Script:Sandbox
    }

    It 'does nothing when Dropbox is already running in this session' {
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'Dropbox')  { return @((New-FakeProcess -SessionId 1)) }
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            return @()
        }
        Invoke-WatchdogCycle | Should -Be 'Running'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
    }

    It 'relaunches Dropbox when it has exited and the relaunch sticks' {
        $Script:launched = $false
        Mock Start-DropboxProcess { $Script:launched = $true }
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            if ($Name -eq 'Dropbox' -and $Script:launched) { return @((New-FakeProcess -SessionId 1)) }
            return @()
        }

        Invoke-WatchdogCycle | Should -Be 'Restarted'
        Should -Invoke Start-DropboxProcess -Times 1 -Exactly
    }

    It 'records the restart in state so the hourly budget is enforced across runs' {
        $Script:launched = $false
        Mock Start-DropboxProcess { $Script:launched = $true }
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            if ($Name -eq 'Dropbox' -and $Script:launched) { return @((New-FakeProcess -SessionId 1)) }
            return @()
        }

        Invoke-WatchdogCycle | Out-Null
        $state = Get-WatchdogState
        @($state.RestartHistoryUtc).Count | Should -Be 1
        $state.LastResult | Should -Be 'Restarted'
        $state.LastRestartUtc | Should -Not -BeNullOrEmpty
    }

    It 'flags a relaunch that does not survive the settle window' {
        Invoke-WatchdogCycle | Should -Be 'RestartDidNotStick'
        (Get-WatchdogState).ConsecutiveFailures | Should -Be 1
    }

    It 'stops restarting once the hourly budget is exhausted' {
        $now = [datetime]::UtcNow
        $state = Get-WatchdogState
        $state.RestartHistoryUtc = @(1..6 | ForEach-Object { $now.AddMinutes(-1 * $_).ToString('o') })
        Save-WatchdogState -State $state | Out-Null

        Invoke-WatchdogCycle | Should -Be 'Throttled'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
        Should -Invoke Write-WatchdogEvent -Times 1 -Exactly -ParameterFilter { $EventId -eq 3001 }
    }

    It 'never launches Dropbox from the non-interactive services session' {
        Mock Get-CurrentSessionId { return 0 }
        Invoke-WatchdogCycle | Should -Be 'NonInteractiveSession'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
    }

    It 'stands down while a machine-wide pause marker is present' {
        Set-Content -LiteralPath (Join-Path $Script:Root 'pause.marker') -Value ''
        Invoke-WatchdogCycle | Should -Be 'Paused'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
    }

    It 'stands down while a per-user pause marker is present' {
        $userDir = Join-Path $env:LOCALAPPDATA 'DropboxWatchdog'
        New-Item -ItemType Directory -Path $userDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $userDir 'pause.marker') -Value ''
        Invoke-WatchdogCycle | Should -Be 'Paused'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
    }

    It 'reports NotInstalled rather than failing when this user has no Dropbox' {
        Mock Get-DropboxLaunchTarget { return $null }
        Invoke-WatchdogCycle | Should -Be 'NotInstalled'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
    }

    It 'yields to a Dropbox updater instead of racing it' {
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'explorer')     { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            if ($Name -eq 'DropboxUpdate'){ return @((New-FakeProcess -SessionId 1 -Name 'DropboxUpdate')) }
            return @()
        }
        Invoke-WatchdogCycle | Should -Be 'MaintenanceInProgress'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
    }

    It 'does not launch Dropbox while the session is logging off' {
        Mock Get-ProcessByName { return @() }   # no explorer -> desktop is gone
        Invoke-WatchdogCycle | Should -Be 'SessionNotReady'
        Should -Invoke Start-DropboxProcess -Times 0 -Exactly
    }

    It 'records its language mode in the heartbeat for remote reporting' {
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'Dropbox')  { return @((New-FakeProcess -SessionId 1)) }
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            return @()
        }
        Invoke-WatchdogCycle | Out-Null
        $state = Get-Content -LiteralPath (Join-Path $env:LOCALAPPDATA 'DropboxWatchdog/state.json') -Raw | ConvertFrom-Json
        $state.LanguageMode | Should -Not -BeNullOrEmpty
    }

    It 'writes a heartbeat the detection script can read on every cycle' {
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'Dropbox')  { return @((New-FakeProcess -SessionId 1)) }
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            return @()
        }
        Invoke-WatchdogCycle | Out-Null

        $statePath = Join-Path $env:LOCALAPPDATA 'DropboxWatchdog/state.json'
        Test-Path -LiteralPath $statePath | Should -BeTrue
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $state.LastCheckUtc | Should -Not -BeNullOrEmpty
        [datetime]::Parse($state.LastCheckUtc, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind) | Should -BeOfType [datetime]
    }

    It 'surfaces the crash evidence and the resolved executable in the restart log line' {
        Invoke-WatchdogCycle | Out-Null
        $log = Get-Content -LiteralPath (Join-Path $env:LOCALAPPDATA 'DropboxWatchdog/watchdog.log') -Raw
        $log | Should -Match 'faulting module ntdll\.dll'
        $log | Should -Match ([regex]::Escape($Script:Target.Path))
        $log | Should -Not -Match 'System\.Object\[\]'
    }

    It 'returns exactly one result object, never log lines alongside it' {
        $output = @(Invoke-WatchdogCycle)
        $output.Count | Should -Be 1
        $output[0] | Should -BeOfType [string]
    }

    It 'survives an unexpected failure and reports it instead of throwing' {
        Mock Get-DropboxLaunchTarget { throw 'registry exploded' }
        Invoke-WatchdogCycle | Should -Be 'Error'
        Should -Invoke Write-WatchdogEvent -Times 1 -Exactly -ParameterFilter { $EventId -eq 4000 }
    }
}

Describe 'Session lock' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData  = $Script:Sandbox.ProgramData
        $env:LOCALAPPDATA = $Script:Sandbox.LocalAppData
        Initialize-Watchdog -Root (Join-Path $Script:Sandbox.ProgramData 'DropboxWatchdog') | Out-Null
    }
    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'takes and releases the lock' {
        Set-WatchdogLock | Should -BeTrue
        Test-Path -LiteralPath $Script:Paths.LockPath | Should -BeTrue
        Remove-WatchdogLock | Should -BeTrue
        Test-Path -LiteralPath $Script:Paths.LockPath | Should -BeFalse
    }

    It 'does not treat its own lock as a rival instance' {
        Set-WatchdogLock | Out-Null
        Get-WatchdogLockOwner | Should -BeNullOrEmpty
    }

    It 'reclaims a lock left behind by a dead process' {
        Set-Content -LiteralPath $Script:Paths.LockPath -Value '999999'
        Get-WatchdogLockOwner | Should -BeNullOrEmpty
    }

    It 'reclaims a lock whose PID was reused by an unrelated process' {
        Set-Content -LiteralPath $Script:Paths.LockPath -Value '4242'
        Mock Get-Process { return @{ Id = 4242; Name = 'notepad' } }
        Get-WatchdogLockOwner | Should -BeNullOrEmpty
    }

    It 'respects a lock held by a live PowerShell host' {
        Set-Content -LiteralPath $Script:Paths.LockPath -Value '4242'
        Mock Get-Process { return @{ Id = 4242; Name = 'powershell' } }
        Get-WatchdogLockOwner | Should -Be 4242
    }

    It 'will not release a lock it does not own' {
        Set-Content -LiteralPath $Script:Paths.LockPath -Value '4242'
        Remove-WatchdogLock | Should -BeFalse
        Test-Path -LiteralPath $Script:Paths.LockPath | Should -BeTrue
    }
}

Describe 'Service loop lifecycle' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData  = $Script:Sandbox.ProgramData
        $env:LOCALAPPDATA = $Script:Sandbox.LocalAppData
        $Script:Root = Join-Path $Script:Sandbox.ProgramData 'DropboxWatchdog'
        New-Item -ItemType Directory -Path (Join-Path $Script:Root 'bin') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $Script:Root 'bin/DropboxWatchdog.ps1') -Value '# payload'
        Mock Write-WatchdogEvent { return $true }
        Mock Get-CurrentSessionId { return 1 }
        Mock Get-ProcessByName {
            param($Name)
            if ($Name -eq 'explorer') { return @((New-FakeProcess -SessionId 1 -Name 'explorer')) }
            return @()
        }
        Initialize-Watchdog -Root $Script:Root | Out-Null
    }

    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'keeps running while the payload, config and desktop are all intact' {
        Set-Content -LiteralPath (Join-Path $Script:Root 'bin/version.json') `
            -Value (@{ PayloadVersion = $Script:PayloadVersion; Enabled = $true } | ConvertTo-Json)
        Initialize-Watchdog -Root $Script:Root | Out-Null
        Test-WatchdogShouldContinue | Should -BeTrue
    }

    It 'exits when a newer payload version has been deployed underneath it' {
        Set-Content -LiteralPath (Join-Path $Script:Root 'bin/version.json') `
            -Value (@{ PayloadVersion = '99.0.0'; Enabled = $true } | ConvertTo-Json)
        Test-WatchdogShouldContinue | Should -BeFalse
    }

    It 'exits when the uninstall has disabled the watchdog' {
        Set-Content -LiteralPath (Join-Path $Script:Root 'bin/version.json') `
            -Value (@{ PayloadVersion = $Script:PayloadVersion; Enabled = $false } | ConvertTo-Json)
        Test-WatchdogShouldContinue | Should -BeFalse
    }

    It 'exits when the payload file has been removed' {
        Remove-Item -LiteralPath (Join-Path $Script:Root 'bin/DropboxWatchdog.ps1') -Force
        Test-WatchdogShouldContinue | Should -BeFalse
    }

    It 'exits when the user has logged off' {
        Mock Get-ProcessByName { return @() }
        Test-WatchdogShouldContinue | Should -BeFalse
    }
}

Describe 'Configuration handling' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $Script:ConfigPath = Join-Path $Script:Sandbox.ProgramData 'version.json'
    }
    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'uses safe defaults when no config has been deployed' {
        $config = Get-WatchdogConfig -ConfigPath $Script:ConfigPath
        $config.PollSeconds | Should -Be 45
        $config.Enabled | Should -BeTrue
    }

    It 'honours deployed overrides' {
        Set-Content -LiteralPath $Script:ConfigPath -Value (@{ PollSeconds = 120; MaxRestartsPerHour = 3 } | ConvertTo-Json)
        $config = Get-WatchdogConfig -ConfigPath $Script:ConfigPath
        $config.PollSeconds | Should -Be 120
        $config.MaxRestartsPerHour | Should -Be 3
    }

    It 'clamps a poll interval that would busy-spin the device' {
        Set-Content -LiteralPath $Script:ConfigPath -Value (@{ PollSeconds = 1 } | ConvertTo-Json)
        (Get-WatchdogConfig -ConfigPath $Script:ConfigPath).PollSeconds | Should -Be 15
    }

    It 'falls back to defaults instead of dying on a corrupt config' {
        Set-Content -LiteralPath $Script:ConfigPath -Value '{ this is not json'
        (Get-WatchdogConfig -ConfigPath $Script:ConfigPath).PollSeconds | Should -Be 45
    }
}

Describe 'Logging' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData  = $Script:Sandbox.ProgramData
        $env:LOCALAPPDATA = $Script:Sandbox.LocalAppData
        Mock Write-WatchdogEvent { return $true }
        Initialize-Watchdog -Root (Join-Path $Script:Sandbox.ProgramData 'DropboxWatchdog') | Out-Null
    }
    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'writes to the per-user log file' {
        Write-WatchdogLog -Message 'hello' -Level 'Info' | Out-Null
        (Get-Content -LiteralPath $Script:Paths.LogPath -Raw) | Should -Match 'hello'
    }

    It 'mirrors to the event log only when an event id is supplied' {
        Write-WatchdogLog -Message 'no event' | Out-Null
        Should -Invoke Write-WatchdogEvent -Times 0 -Exactly
        Write-WatchdogLog -Message 'with event' -EventId 2001 | Out-Null
        Should -Invoke Write-WatchdogEvent -Times 1 -Exactly
    }

    It 'rotates the log instead of letting it grow without bound' {
        $logPath = $Script:Paths.LogPath
        New-Item -ItemType Directory -Path (Split-Path -Parent $logPath) -Force | Out-Null
        Set-Content -LiteralPath $logPath -Value ('x' * 2048)
        Invoke-LogRotation -LogPath $logPath -MaxBytes 1024
        Test-Path -LiteralPath "$logPath.1" | Should -BeTrue
        Test-Path -LiteralPath $logPath | Should -BeFalse
    }
}

Describe 'Constrained language mode' {
    # The substantive proof lives in ConstrainedLanguage.Tests.ps1, which runs the real
    # payload inside a genuinely constrained runspace. These cover the reporting helper.

    It 'reports the mode it is running under' {
        Get-PowerShellLanguageMode | Should -Be 'FullLanguage'
    }

    It 'recognises a constrained runspace' {
        Mock Get-PowerShellLanguageMode { return 'ConstrainedLanguage' }
        Test-FullLanguageMode | Should -BeFalse
    }

    It 'does not treat an undeterminable mode as constrained' {
        Mock Get-PowerShellLanguageMode { return 'Unknown' }
        Test-FullLanguageMode | Should -BeTrue
    }

    It 'does not gate execution on language mode' {
        # The payload must attempt to run either way; gating here would disable the
        # watchdog on exactly the locked-down devices that most need it.
        $text = Get-Content -LiteralPath $Script:PayloadFile -Raw
        $text | Should -Not -Match 'exit 3'
    }
}

Describe 'Get-DropboxCrashEvidence' {
    It 'returns the first Application-log record that names Dropbox.exe' {
        Mock Get-WinEvent {
            return @(
                [pscustomobject]@{ ProviderName = 'Application Error'; Id = 1000; Message = "Faulting application name: chrome.exe" },
                [pscustomobject]@{ ProviderName = 'Application Error'; Id = 1000; Message = "Faulting application name: Dropbox.exe`nFaulting module: ntdll.dll" }
            )
        }
        $evidence = Get-DropboxCrashEvidence
        $evidence | Should -Match 'Dropbox\.exe'
        $evidence | Should -Match 'Application Error/1000'
    }

    It 'returns null when the log holds nothing relevant' {
        Mock Get-WinEvent { return @() }
        Get-DropboxCrashEvidence | Should -BeNullOrEmpty
    }
}
