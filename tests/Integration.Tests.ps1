#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    End-to-end checks across the generated scripts: what the remediation writes must be
    exactly what the detection accepts, and a damaged install must be detected and then
    repaired. These are the failures that unit tests on either side alone cannot catch.

    Both scripts are dot-sourced into one scope. They share the generated contract block,
    so the definitions they have in common are byte-identical (Structure.Tests.ps1 asserts
    that); the detection script is loaded last so its versions of the shared helpers win.
#>

BeforeAll {
    $env:DBW_TEST_IMPORT = '1'
    Import-Module "$PSScriptRoot/shims/WindowsShims.psm1" -Force -Global
    Import-Module "$PSScriptRoot/shims/TestHelpers.psm1" -Force -Global

    $Script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $Script:RepoRoot 'build/Remediate-DropboxWatchdog.ps1')
    . (Join-Path $Script:RepoRoot 'build/Detect-DropboxWatchdog.ps1')
}

Describe 'Remediation and detection agree' {
    BeforeEach {
        $Script:Sandbox = New-TestSandbox
        $env:ProgramData = $Script:Sandbox.ProgramData
        $env:SystemRoot  = 'C:\Windows'
        $Script:Contract = Get-WatchdogContract

        Mock Invoke-Icacls { return [pscustomobject]@{ ExitCode = 0; Output = '' } }
        Mock Register-EventSource { return $true }
        Mock Register-WatchdogTask { return $true }
        Mock Test-HeadlessConsoleSupported { return $true }
        Mock Get-InteractiveUserProfile { return @() }

        # Stand in for the task the (mocked) registration would have created.
        $Script:TaskRegistered = $false
        Mock Get-WatchdogScheduledTask {
            if (-not $Script:TaskRegistered) { return $null }
            New-FakeScheduledTask -Execute $Script:Contract.TaskExecute -Arguments $Script:Contract.TaskArgument
        }
        Mock Install-WatchdogTask {
            param($Contract)
            $Script:TaskRegistered = $true
            return $true
        }
    }

    AfterEach { Remove-TestSandbox -Sandbox $Script:Sandbox }

    It 'reports non-compliant on a device that has never been remediated' {
        $result = Invoke-Detection
        $result.ExitCode | Should -Be 1
        $result.Message | Should -Match 'payload missing'
    }

    It 'reports compliant immediately after a successful remediation' {
        Invoke-Remediation | Out-Null
        $result = Invoke-Detection
        $result.ExitCode | Should -Be 0 -Because "detection said: $($result.Message)"
    }

    It 'is idempotent: a second remediation leaves the device compliant' {
        Invoke-Remediation | Out-Null
        Invoke-Remediation | Out-Null
        (Invoke-Detection).ExitCode | Should -Be 0
    }

    It 'detects a tampered payload and repairs it' {
        Invoke-Remediation | Out-Null
        Add-Content -LiteralPath $Script:Contract.PayloadPath -Value '# unauthorised edit'

        $broken = Invoke-Detection
        $broken.ExitCode | Should -Be 1
        $broken.Message | Should -Match 'payload hash mismatch'

        Invoke-Remediation | Out-Null
        (Invoke-Detection).ExitCode | Should -Be 0
        (Get-Content -LiteralPath $Script:Contract.PayloadPath -Raw) | Should -Not -Match 'unauthorised edit'
    }

    It 'detects a deleted install directory and rebuilds it' {
        Invoke-Remediation | Out-Null
        Remove-Item -LiteralPath $Script:Contract.InstallRoot -Recurse -Force

        (Invoke-Detection).ExitCode | Should -Be 1
        Invoke-Remediation | Out-Null
        (Invoke-Detection).ExitCode | Should -Be 0
    }

    It 'treats a stale payload version as non-compliant until remediation reruns' {
        Invoke-Remediation | Out-Null
        $config = Get-Content -LiteralPath $Script:Contract.ConfigPath -Raw | ConvertFrom-Json
        $config.PayloadVersion = '0.0.1'
        Set-Content -LiteralPath $Script:Contract.ConfigPath -Value ($config | ConvertTo-Json -Depth 4)

        (Invoke-Detection).ExitCode | Should -Be 1
        Invoke-Remediation | Out-Null
        (Invoke-Detection).ExitCode | Should -Be 0
    }

    It 'installs a payload the watchdog itself accepts as current' {
        # The deployed config must satisfy the running watchdog's own version check,
        # otherwise every watchdog loop would exit immediately after starting.
        Invoke-Remediation | Out-Null

        $deployed = Get-Content -LiteralPath $Script:Contract.ConfigPath -Raw | ConvertFrom-Json
        $declared = ([regex]::Match(
            (Get-Content -LiteralPath $Script:Contract.PayloadPath -Raw),
            "\`$Script:PayloadVersion\s*=\s*'([^']+)'")).Groups[1].Value

        $declared | Should -Not -BeNullOrEmpty
        $deployed.PayloadVersion | Should -Be $declared
        $deployed.Enabled | Should -BeTrue
    }
}
