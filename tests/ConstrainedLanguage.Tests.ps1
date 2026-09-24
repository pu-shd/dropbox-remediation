#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Proves the watchdog payload runs under ConstrainedLanguage - the mode AppLocker
    script enforcement and WDAC impose on standard users, which is exactly the context
    the payload runs in.

    This matters because the alternative is asking someone to log on to a managed device
    and check $ExecutionContext.SessionState.LanguageMode by hand. The checks run in a
    child process because language mode can only be tightened, never relaxed.
#>

BeforeAll {
    $Script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $Script:Payload  = Join-Path $Script:RepoRoot 'src/payload/DropboxWatchdog.ps1'
    $Script:Runner   = Join-Path $PSScriptRoot 'clm/Invoke-ConstrainedLanguageChecks.ps1'
    $Script:Sandbox  = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-clm-" + [Guid]::NewGuid().ToString('n'))

    $pwshPath = (Get-Process -Id $PID).Path
    if (-not $pwshPath) { $pwshPath = 'pwsh' }

    $Script:Output = & $pwshPath -NoLogo -NoProfile -File $Script:Runner `
        -PayloadPath $Script:Payload -Sandbox $Script:Sandbox 2>&1 | ForEach-Object { [string]$_ }
    $Script:Lines = @($Script:Output)
}

AfterAll {
    if ($Script:Sandbox -and (Test-Path -LiteralPath $Script:Sandbox)) {
        Remove-Item -LiteralPath $Script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Payload under ConstrainedLanguage' {
    It 'actually ran the checks in a constrained runspace' {
        $countLine = @($Script:Lines | Where-Object { $_ -like 'CHECKS *' })
        $countLine.Count | Should -Be 1 -Because "the child process must finish; output was: $($Script:Lines -join ' | ')"

        $count = [int](($countLine[0] -split ' ')[1])
        $count | Should -BeGreaterThan 15 -Because 'a truncated run must not look like a pass'

        $Script:Lines | Should -Contain 'PASS runspace is actually constrained'
    }

    It 'passes every constrained-language check' {
        $failures = @($Script:Lines | Where-Object { $_ -like 'FAIL *' })
        $failures.Count | Should -Be 0 -Because ($failures -join ' | ')
    }

    It 'reports one result per check, with none silently missing' {
        $results = @($Script:Lines | Where-Object { $_ -like 'PASS *' -or $_ -like 'FAIL *' })
        $countLine = @($Script:Lines | Where-Object { $_ -like 'CHECKS *' })[0]
        $results.Count | Should -Be ([int](($countLine -split ' ')[1]))
    }

    It 'restarts Dropbox end to end while constrained' {
        $Script:Lines | Should -Contain 'PASS cycle relaunches Dropbox when it has exited'
    }

    It 'still applies crash-loop protection while constrained' {
        $Script:Lines | Should -Contain 'PASS cycle throttles a crash loop'
    }

    It 'records the language mode so it can be read from the Intune portal' {
        $Script:Lines | Should -Contain 'PASS state records the language mode for remote reporting'
    }
}
