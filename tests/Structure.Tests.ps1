#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Structural guarantees that unit tests cannot express: the generated scripts agree
    with each other and with src/, they parse, they stay inside Windows PowerShell 5.1,
    and the shell tooling is syntactically valid.
#>

BeforeAll {
    $Script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $Script:BuildDir = Join-Path $Script:RepoRoot 'build'
    $Script:SourcePayload = Join-Path $Script:RepoRoot 'src/payload/DropboxWatchdog.ps1'

    $Script:BuiltScripts = @(
        Join-Path $Script:BuildDir 'Detect-DropboxWatchdog.ps1'
        Join-Path $Script:BuildDir 'Remediate-DropboxWatchdog.ps1'
        Join-Path $Script:BuildDir 'DetectRemoval-DropboxWatchdog.ps1'
        Join-Path $Script:BuildDir 'Uninstall-DropboxWatchdog.ps1'
    )

    function Script:Get-ContractRegion {
        param([string]$Path)
        $text = Get-Content -LiteralPath $Path -Raw
        $pattern = '(?s)#region SHARED-CONTRACT.*?#endregion SHARED-CONTRACT'
        $match = [regex]::Match($text, $pattern)
        if (-not $match.Success) { return $null }
        return $match.Value
    }
}

Describe 'Build output' {
    It 'produced every generated script plus a manifest' {
        foreach ($path in $Script:BuiltScripts) {
            Test-Path -LiteralPath $path | Should -BeTrue -Because "$path should exist after scripts/build.sh"
        }
        Test-Path -LiteralPath (Join-Path $Script:BuildDir 'manifest.json') | Should -BeTrue
    }

    It 'left no unsubstituted build placeholders' {
        foreach ($path in $Script:BuiltScripts) {
            (Get-Content -LiteralPath $path -Raw) | Should -Not -Match '@@[A-Z_]+@@' -Because "$path is fully expanded"
        }
    }

    It 'contains only ASCII, so Windows PowerShell 5.1 cannot misread it' {
        # Intune stores and replays the file as-is. Windows PowerShell 5.1 treats a
        # BOM-less file as ANSI, so a curly quote or em dash pasted into a string or
        # a log message would arrive on the device corrupted. The payload counts too:
        # it is base64-encoded into the remediation, so bad bytes there are invisible
        # in the generated scripts but are written back out and executed verbatim.
        foreach ($path in (@($Script:BuiltScripts) + @($Script:SourcePayload))) {
            $bytes = [System.IO.File]::ReadAllBytes($path)
            $offenders = @()
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $b = $bytes[$i]
                if ($b -gt 126 -or ($b -lt 32 -and $b -ne 9 -and $b -ne 10 -and $b -ne 13)) {
                    $offenders += ('byte 0x{0:X2} at offset {1}' -f $b, $i)
                    if ($offenders.Count -ge 3) { break }
                }
            }
            @($offenders).Count | Should -Be 0 -Because "$(Split-Path -Leaf $path) must be pure ASCII: $($offenders -join ', ')"
        }
    }

    It 'has no UTF-8 BOM, which Intune would carry into the executed file' {
        foreach ($path in (@($Script:BuiltScripts) + @($Script:SourcePayload))) {
            $head = [System.IO.File]::ReadAllBytes($path)[0..2]
            (($head[0] -eq 0xEF) -and ($head[1] -eq 0xBB) -and ($head[2] -eq 0xBF)) |
                Should -BeFalse -Because "$(Split-Path -Leaf $path) should not start with a BOM"
        }
    }

    It 'stays under the 200 KB Intune script size limit' {
        foreach ($path in $Script:BuiltScripts) {
            (Get-Item -LiteralPath $path).Length | Should -BeLessThan 200000
        }
    }
}

Describe 'Shared contract consistency' {
    It 'is present in every generated script' {
        foreach ($path in $Script:BuiltScripts) {
            Script:Get-ContractRegion -Path $path | Should -Not -BeNullOrEmpty -Because "$path must carry the contract"
        }
    }

    It 'is byte-identical across every generated script' {
        $regions = @($Script:BuiltScripts | ForEach-Object { Script:Get-ContractRegion -Path $_ })
        $distinct = @($regions | Select-Object -Unique)
        $distinct.Count | Should -Be 1 -Because 'every generated script must agree on paths, task shape and payload version'
    }

    It 'stamps the real payload hash into the contract' {
        $expected = (Get-FileHash -LiteralPath $Script:SourcePayload -Algorithm SHA256).Hash
        $region = Script:Get-ContractRegion -Path $Script:BuiltScripts[0]
        $region | Should -Match ([regex]::Escape($expected))
    }

    It 'stamps the payload version declared in the payload itself' {
        $declared = ([regex]::Match(
            (Get-Content -LiteralPath $Script:SourcePayload -Raw),
            "\`$Script:PayloadVersion\s*=\s*'([^']+)'")).Groups[1].Value
        $declared | Should -Not -BeNullOrEmpty
        $region = Script:Get-ContractRegion -Path $Script:BuiltScripts[0]
        $region | Should -Match ("PayloadVersion\s*=\s*'" + [regex]::Escape($declared) + "'")
    }
}

Describe 'PowerShell syntax and 5.1 compatibility' {
    BeforeAll {
        $Script:AllScripts = @($Script:BuiltScripts) + @($Script:SourcePayload)
    }

    It 'parses without errors' {
        foreach ($path in $Script:AllScripts) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) | Out-Null
            @($errors).Count | Should -Be 0 -Because "$path must parse cleanly: $(($errors | ForEach-Object { $_.Message }) -join '; ')"
        }
    }

    It 'uses no PowerShell 7-only language features' {
        # Intune runs these under Windows PowerShell 5.1, which has no ternary operator,
        # no null-coalescing and no && / || pipeline chains.
        foreach ($path in $Script:AllScripts) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)

            $ternary = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TernaryExpressionAst] }, $true)
            @($ternary).Count | Should -Be 0 -Because "$path must not use the ternary operator"

            $chains = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.PipelineChainAst] }, $true)
            @($chains).Count | Should -Be 0 -Because "$path must not use && or || pipeline chains"
        }
    }

    It 'uses no null-coalescing operators' {
        foreach ($path in $Script:AllScripts) {
            $text = Get-Content -LiteralPath $path -Raw
            $text | Should -Not -Match '\?\?=?' -Because "$path must not use ?? or ??="
            $text | Should -Not -Match '\$\w+\?\.' -Because "$path must not use null-conditional member access"
        }
    }

    It 'guards its entry point so the test suite can import it safely' {
        foreach ($path in $Script:AllScripts) {
            (Get-Content -LiteralPath $path -Raw) | Should -Match 'if \(-not \$env:DBW_TEST_IMPORT\)'
        }
    }

    It 'always terminates with an explicit exit code' {
        foreach ($path in $Script:BuiltScripts) {
            $text = Get-Content -LiteralPath $path -Raw
            $text | Should -Match 'exit 1'
            $text | Should -Match 'exit \(\[int\]\$result\.ExitCode\)'
        }
    }
}

Describe 'PSScriptAnalyzer' {
    BeforeAll {
        $Script:AnalyzerAvailable = $null -ne (Get-Module -ListAvailable -Name PSScriptAnalyzer)
    }

    It 'is installed in the test image' {
        $Script:AnalyzerAvailable | Should -BeTrue -Because 'static analysis is part of the suite, not optional'
    }

    It 'reports no Error-severity findings' {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $targets = @($Script:BuiltScripts) + @($Script:SourcePayload)
        $findings = @()
        foreach ($path in $targets) {
            $findings += @(Invoke-ScriptAnalyzer -Path $path -Severity Error)
        }
        $detail = ($findings | ForEach-Object { "$($_.ScriptName):$($_.Line) $($_.RuleName)" }) -join '; '
        @($findings).Count | Should -Be 0 -Because "analyzer errors: $detail"
    }

    It 'does not assign to PowerShell automatic variables' {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $targets = @($Script:BuiltScripts) + @($Script:SourcePayload)
        $findings = @()
        foreach ($path in $targets) {
            $findings += @(Invoke-ScriptAnalyzer -Path $path -IncludeRule PSAvoidAssignmentToAutomaticVariable)
        }
        $detail = ($findings | ForEach-Object { "$($_.ScriptName):$($_.Line) $($_.Message)" }) -join '; '
        @($findings).Count | Should -Be 0 -Because "automatic variable assignments: $detail"
    }
}

Describe 'Shell tooling' {
    BeforeAll {
        $Script:ShellScripts = @(Get-ChildItem -LiteralPath (Join-Path $Script:RepoRoot 'scripts') -Filter '*.sh' -Recurse)
        $Script:ZshPath = (Get-Command zsh -ErrorAction SilentlyContinue)
    }

    It 'ships the build, test, deploy, update and teardown scripts' {
        $names = @($Script:ShellScripts | ForEach-Object { $_.Name })
        foreach ($expected in @('build.sh', 'test.sh', 'deploy-intune.sh', 'update-intune.sh',
                                    'teardown-intune.sh', 'intune-login.sh', 'graph.sh')) {
            $names | Should -Contain $expected
        }
    }

    It 'marks every shell script executable' {
        foreach ($file in $Script:ShellScripts) {
            $mode = (Get-Item -LiteralPath $file.FullName).UnixMode
            $mode | Should -Match '^.{3}x' -Because "$($file.Name) must be executable"
        }
    }

    It 'passes zsh syntax checking' {
        $Script:ZshPath | Should -Not -BeNullOrEmpty -Because 'the test image installs zsh so these can be checked'
        foreach ($file in $Script:ShellScripts) {
            $output = & zsh -n $file.FullName 2>&1
            $LASTEXITCODE | Should -Be 0 -Because "$($file.Name) must be valid zsh: $output"
        }
    }

    It 'declares a zsh shebang' {
        foreach ($file in $Script:ShellScripts) {
            (Get-Content -LiteralPath $file.FullName -TotalCount 1) | Should -Match 'zsh'
        }
    }
}
