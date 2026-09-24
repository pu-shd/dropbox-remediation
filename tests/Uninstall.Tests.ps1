#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<# Unit tests for the built uninstall script. #>

BeforeAll {
    $env:DBW_TEST_IMPORT = '1'
    Import-Module "$PSScriptRoot/shims/WindowsShims.psm1" -Force -Global
    Import-Module "$PSScriptRoot/shims/TestHelpers.psm1" -Force -Global

    $Script:UninstallScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'build/Uninstall-DropboxWatchdog.ps1'
    if (-not (Test-Path -LiteralPath $Script:UninstallScript)) {
        throw "build/Uninstall-DropboxWatchdog.ps1 not found. Run scripts/build.sh first."
    }
    . $Script:UninstallScript
}

Describe 'Invoke-Uninstall' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData = $Script:Sandbox.ProgramData
        $env:SystemRoot  = 'C:\Windows'
        $env:PUBLIC      = Join-Path $Script:Sandbox.Root 'Users/Public'
        $Script:Contract = Get-WatchdogContract

        New-Item -ItemType Directory -Path $Script:Contract.BinDir -Force | Out-Null
        Set-Content -LiteralPath $Script:Contract.PayloadPath -Value '# payload'
        Set-Content -LiteralPath $Script:Contract.ConfigPath `
            -Value (@{ PayloadVersion = '1.0.0'; Enabled = $true } | ConvertTo-Json)

        Mock Unregister-WatchdogEventSource { return $true }
    }
    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'disables the config before deleting files so running loops stand down cleanly' {
        $Script:order = @()
        Mock Disable-WatchdogConfig { $Script:order += 'disable'; return $true }
        Mock Remove-WatchdogFiles  { $Script:order += 'remove'; return $true }
        Mock Unregister-WatchdogTask { $Script:order += 'untask'; return $true }

        Invoke-Uninstall | Out-Null
        $Script:order[0] | Should -Be 'disable'
        $Script:order | Should -Contain 'untask'
        ($Script:order.IndexOf('remove')) | Should -BeGreaterThan ($Script:order.IndexOf('disable'))
    }

    It 'actually flips Enabled to false in the deployed config' {
        Disable-WatchdogConfig -Contract $Script:Contract | Should -BeTrue
        $config = Get-Content -LiteralPath $Script:Contract.ConfigPath -Raw | ConvertFrom-Json
        $config.Enabled | Should -BeFalse
        $config.PayloadVersion | Should -Be 'uninstalled'
    }

    It 'removes the install directory' {
        Mock Unregister-WatchdogTask { return $true }
        Invoke-Uninstall | Out-Null
        Test-Path -LiteralPath $Script:Contract.InstallRoot | Should -BeFalse
    }

    It 'removes per-user watchdog data across all profiles' {
        Mock Unregister-WatchdogTask { return $true }
        foreach ($name in @('alice', 'bob')) {
            $dir = Join-Path $Script:Sandbox.Root "Users/$name/AppData/Local/DropboxWatchdog"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir 'state.json') -Value '{}'
        }
        Invoke-Uninstall | Out-Null
        Test-Path -LiteralPath (Join-Path $Script:Sandbox.Root 'Users/alice/AppData/Local/DropboxWatchdog') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $Script:Sandbox.Root 'Users/bob/AppData/Local/DropboxWatchdog') | Should -BeFalse
    }

    It 'keeps per-user logs when asked to' {
        Mock Unregister-WatchdogTask { return $true }
        $dir = Join-Path $Script:Sandbox.Root 'Users/alice/AppData/Local/DropboxWatchdog'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Invoke-Uninstall -KeepUserLogs $true | Out-Null
        Test-Path -LiteralPath $dir | Should -BeTrue
    }

    It 'is a clean no-op on a device that never had the watchdog' {
        Remove-Item -LiteralPath $Script:Contract.InstallRoot -Recurse -Force
        Mock Unregister-WatchdogTask { return $false }
        Mock Unregister-WatchdogEventSource { return $false }
        $result = Invoke-Uninstall
        $result.ExitCode | Should -Be 0
        $result.Message | Should -Match 'nothing to do'
    }

    It 'reports success once the task has been unregistered' {
        Mock Unregister-WatchdogTask { return $true }
        $result = Invoke-Uninstall
        $result.ExitCode | Should -Be 0
        $result.Message | Should -Match 'scheduled task removed'
    }
}
