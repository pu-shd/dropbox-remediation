#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Tests scripts/intune-login.sh by running it against a fake `az` on PATH and
    inspecting the arguments it actually passes.

    The regression these exist for: `az login --username <upn>` without a password puts
    the CLI into resource-owner-password mode, which cannot satisfy MFA and fails with
    AADSTS50076. Interactive auth takes no account hint, so the account must be VERIFIED
    after login instead of passed in.
#>

BeforeAll {
    $Script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $Script:Script   = Join-Path $Script:RepoRoot 'scripts/intune-login.sh'

    function Script:New-FakeJwt {
        param([hashtable]$Claims)
        $enc = {
            param($o)
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).
                TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }
        "$(& $enc @{ alg = 'none' }).$(& $enc $Claims).sig"
    }

    function Script:Invoke-Login {
        <#
            Runs intune-login.sh with a fake az that records its argv.
            Returns the recorded argv lines plus the script's own output and exit code.
        #>
        param(
            [string]$Account = 'intune-admin@contoso.com',
            [string]$SignedInAs = 'intune-admin@contoso.com',
            [string[]]$ExtraArgs = @()
        )

        $work = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-login-" + [Guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $azLog = Join-Path $work 'az.log'
        $bin   = Join-Path $work 'bin'
        New-Item -ItemType Directory -Path $bin -Force | Out-Null

        $token = Script:New-FakeJwt @{
            upn = $SignedInAs
            tid = '11111111-1111-1111-1111-111111111111'
            scp = 'DeviceManagementConfiguration.ReadWrite.All'
        }

        $fakeAz = @"
#!/usr/bin/env zsh
print -- "ARGV: `$*" >> '$azLog'
if [[ "`$1" == "account" && "`$2" == "show" ]]; then print -- '$SignedInAs'; exit 0; fi
if [[ "`$1" == "account" && "`$2" == "get-access-token" ]]; then print -- '$token'; exit 0; fi
exit 0
"@
        Set-Content -LiteralPath (Join-Path $bin 'az') -Value $fakeAz
        & chmod +x (Join-Path $bin 'az')

        $runner = Join-Path $work 'run.zsh'
        $argLine = (@("--account", $Account, "--profile", (Join-Path $work 'profile'), "--no-env") + $ExtraArgs |
            ForEach-Object { "'$_'" }) -join ' '
        Set-Content -LiteralPath $runner -Value @"
export PATH='$bin':`$PATH
zsh '$($Script:Script)' $argLine
"@
        $stdout = & zsh $runner 2>&1 | Out-String
        $code = $LASTEXITCODE

        $argv = @()
        if (Test-Path -LiteralPath $azLog) { $argv = @(Get-Content -LiteralPath $azLog) }

        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{ Argv = $argv; Output = $stdout; ExitCode = $code }
    }
}

Describe 'intune-login.sh interactive login' {
    It 'never passes --username, which would force password auth and break MFA' {
        $r = Script:Invoke-Login
        $login = @($r.Argv | Where-Object { $_ -match 'ARGV: login' })
        $login.Count | Should -BeGreaterThan 0 -Because "az login should have been invoked; got: $($r.Argv -join ' | ')"
        $login -join ' ' | Should -Not -Match '--username' -Because 'AADSTS50076: ROPC cannot satisfy MFA'
        $login -join ' ' | Should -Not -Match '--password'
    }

    It 'allows an account with no Azure subscription' {
        $r = Script:Invoke-Login
        ($r.Argv | Where-Object { $_ -match 'ARGV: login' }) -join ' ' |
            Should -Match '--allow-no-subscriptions'
    }

    It 'supports device-code auth as the fallback when the browser picks the wrong account' {
        $r = Script:Invoke-Login -ExtraArgs @('--device-code')
        ($r.Argv | Where-Object { $_ -match 'ARGV: login' }) -join ' ' |
            Should -Match '--use-device-code'
    }

    It 'does not pass --use-device-code unless asked' {
        $r = Script:Invoke-Login
        ($r.Argv | Where-Object { $_ -match 'ARGV: login' }) -join ' ' |
            Should -Not -Match '--use-device-code'
    }

    It 'tells the user which account to pick, since interactive auth takes no hint' {
        $r = Script:Invoke-Login
        $r.Output | Should -Match 'sign in as: intune-admin@contoso\.com'
    }

    It 'succeeds when the account that comes back is the one requested' {
        $r = Script:Invoke-Login
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match 'ready'
    }

    It 'rejects the login when the browser reuses a different account' {
        $r = Script:Invoke-Login -Account 'intune-admin@contoso.com' -SignedInAs 'everyday-user@contoso.com'
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'signed in as everyday-user@contoso\.com, not intune-admin@contoso\.com'
        $r.Output | Should -Match 'device-code'
    }

    It 'signs the wrong account back out of this profile rather than leaving it active' {
        $r = Script:Invoke-Login -Account 'intune-admin@contoso.com' -SignedInAs 'everyday-user@contoso.com'
        ($r.Argv -join ' ') | Should -Match 'ARGV: logout'
    }
}
