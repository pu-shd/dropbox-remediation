#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Tests for diagnostics/probe - the no-privilege scripts used to work out why a
    remediation package will not save or assign.

    A probe that misbehaves would send the investigation the wrong way, so these run
    the real scripts as child processes, including under ConstrainedLanguage, and
    check exit codes, output and the marker round trip.
#>

BeforeAll {
    $Script:RepoRoot  = Split-Path -Parent $PSScriptRoot
    $Script:ProbeDir  = Join-Path $Script:RepoRoot 'diagnostics/probe'
    $Script:Detect    = Join-Path $Script:ProbeDir 'Probe-Detect.ps1'
    $Script:Remediate = Join-Path $Script:ProbeDir 'Probe-Remediate.ps1'
    $Script:Platform  = Join-Path $Script:ProbeDir 'Probe-PlatformScript.ps1'
    $Script:All       = @($Script:Detect, $Script:Remediate, $Script:Platform)

    $Script:Pwsh = (Get-Process -Id $PID).Path
    if (-not $Script:Pwsh) { $Script:Pwsh = 'pwsh' }

    function Script:Invoke-Probe {
        <# Runs one probe in a fresh process with TEMP pointed at the sandbox. #>
        param([string]$Path, [switch]$Constrained)
        $prefix = ''
        if ($Constrained) { $prefix = "`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " }
        $command = "$prefix. '$Path'"
        $output = & $Script:Pwsh -NoLogo -NoProfile -NonInteractive -Command $command 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output.Trim() }
    }
}

Describe 'Probe scripts are upload-safe' {
    It 'ships all three probes' {
        foreach ($path in $Script:All) {
            Test-Path -LiteralPath $path | Should -BeTrue -Because "$path should exist"
        }
    }

    It 'parses without errors' {
        foreach ($path in $Script:All) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) | Out-Null
            @($errors).Count | Should -Be 0 -Because "$(Split-Path -Leaf $path): $(($errors | ForEach-Object Message) -join '; ')"
        }
    }

    It 'is pure ASCII with no BOM' {
        foreach ($path in $Script:All) {
            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bad = @($bytes | Where-Object { $_ -gt 126 -or ($_ -lt 32 -and $_ -ne 9 -and $_ -ne 10 -and $_ -ne 13) })
            $bad.Count | Should -Be 0 -Because "$(Split-Path -Leaf $path) must upload cleanly and run under Windows PowerShell 5.1"
        }
    }

    It 'uses no PowerShell 7-only syntax' {
        foreach ($path in $Script:All) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
            @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TernaryExpressionAst] }, $true)).Count | Should -Be 0
            @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.PipelineChainAst] }, $true)).Count | Should -Be 0
            (Get-Content -LiteralPath $path -Raw) | Should -Not -Match '\?\?'
        }
    }

    It 'makes no call that would need elevation' {
        # The point of the probe is to isolate the problem from permissions, so it must
        # not touch the registry, services, scheduled tasks, the event log or ACLs.
        foreach ($path in $Script:All) {
            $text = Get-Content -LiteralPath $path -Raw
            $text | Should -Not -Match 'HKLM:|HKCU:|Register-ScheduledTask|New-Service|Set-Service|EventLog|icacls|Set-Acl|ProgramData'
        }
    }
}

Describe 'Remediation probe round trip' {
    BeforeEach {
        $Script:Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-probe-" + [Guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $Script:Sandbox -Force | Out-Null
        $Script:OldTemp = $env:TEMP
        $env:TEMP = $Script:Sandbox
        $Script:Marker = Join-Path $Script:Sandbox 'IntuneRemediationProbe.marker'
    }
    AfterEach {
        $env:TEMP = $Script:OldTemp
        Remove-Item -LiteralPath $Script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'detection exits 1 before remediation has run, so the remediation fires' {
        $r = Script:Invoke-Probe -Path $Script:Detect
        $r.ExitCode | Should -Be 1
        $r.Output | Should -Match '^PROBE NOT_COMPLIANT'
    }

    It 'remediation writes the marker and exits 0' {
        $r = Script:Invoke-Probe -Path $Script:Remediate
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match '^PROBE REMEDIATED'
        Test-Path -LiteralPath $Script:Marker | Should -BeTrue
    }

    It 'detection exits 0 once remediation has run' {
        Script:Invoke-Probe -Path $Script:Remediate | Out-Null
        $r = Script:Invoke-Probe -Path $Script:Detect
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match '^PROBE COMPLIANT: remediation ran at \d{4}-\d{2}-\d{2}T'
    }

    It 'reports the context fields the decision matrix relies on' {
        $r = Script:Invoke-Probe -Path $Script:Detect
        foreach ($field in @('user=', 'ps=', 'lang=FullLanguage', 'session=')) {
            $r.Output | Should -Match ([regex]::Escape($field))
        }
    }

    It 'keeps each output within the Intune 2048-character limit on a single line' {
        foreach ($path in @($Script:Detect, $Script:Remediate, $Script:Detect)) {
            $r = Script:Invoke-Probe -Path $path
            $r.Output.Length | Should -BeLessOrEqual 2048
            @($r.Output -split "`n").Count | Should -Be 1
        }
    }
}

Describe 'Probes under ConstrainedLanguage' {
    # The R1 probe runs as the signed-in user, who is the one AppLocker or WDAC would
    # constrain. It has to work there, and say so.
    BeforeEach {
        $Script:Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-probe-clm-" + [Guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $Script:Sandbox -Force | Out-Null
        $Script:OldTemp = $env:TEMP
        $env:TEMP = $Script:Sandbox
    }
    AfterEach {
        $env:TEMP = $Script:OldTemp
        Remove-Item -LiteralPath $Script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'runs the full detect, remediate, detect cycle constrained' {
        $first = Script:Invoke-Probe -Path $Script:Detect -Constrained
        $first.ExitCode | Should -Be 1 -Because $first.Output
        $first.Output | Should -Match '^PROBE NOT_COMPLIANT'

        $fix = Script:Invoke-Probe -Path $Script:Remediate -Constrained
        $fix.ExitCode | Should -Be 0 -Because $fix.Output
        $fix.Output | Should -Match '^PROBE REMEDIATED'

        $second = Script:Invoke-Probe -Path $Script:Detect -Constrained
        $second.ExitCode | Should -Be 0 -Because $second.Output
        $second.Output | Should -Match '^PROBE COMPLIANT'
    }

    It 'reports that it ran constrained, so a constrained user shows up in the portal' {
        $r = Script:Invoke-Probe -Path $Script:Detect -Constrained
        $r.Output | Should -Match 'lang=ConstrainedLanguage'
        $r.Output | Should -Not -Match 'PROBE ERROR'
    }

    It 'runs the platform script constrained' {
        $r = Script:Invoke-Probe -Path $Script:Platform -Constrained
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match 'PROBE PLATFORM SCRIPT RAN'
    }
}

Describe 'Platform script probe' {
    BeforeEach {
        $Script:Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-probe-plat-" + [Guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $Script:Sandbox -Force | Out-Null
        $Script:OldTemp = $env:TEMP
        $env:TEMP = $Script:Sandbox
    }
    AfterEach {
        $env:TEMP = $Script:OldTemp
        Remove-Item -LiteralPath $Script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'exits 0 and leaves a log line, since the portal shows no output for platform scripts' {
        $r = Script:Invoke-Probe -Path $Script:Platform
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $log = Join-Path $Script:Sandbox 'IntunePlatformScriptProbe.log'
        Test-Path -LiteralPath $log | Should -BeTrue
        (Get-Content -LiteralPath $log -Raw) | Should -Match 'PROBE PLATFORM SCRIPT RAN \| user='
    }

    It 'appends on each run rather than overwriting' {
        Script:Invoke-Probe -Path $Script:Platform | Out-Null
        Script:Invoke-Probe -Path $Script:Platform | Out-Null
        $log = Join-Path $Script:Sandbox 'IntunePlatformScriptProbe.log'
        @(Get-Content -LiteralPath $log).Count | Should -Be 2
    }
}
