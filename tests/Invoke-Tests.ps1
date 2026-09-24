<#
.SYNOPSIS
    Test entry point. Builds the Intune scripts from src/, then runs the Pester suite.

.DESCRIPTION
    Used by the Docker image and by scripts/test.sh. Fails the run if:
      * the build fails,
      * any test fails, or
      * fewer than $MinimumTests tests actually executed.

    The last condition matters: a suite that silently collected nothing would
    otherwise exit 0 and look like a pass.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [int]$MinimumTests = 70,
    [switch]$SkipBuild
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path $repoRoot 'tests'
$buildDir = Join-Path $repoRoot 'build'

if (-not $SkipBuild) {
    Write-Host '=== Building Intune scripts from src/ ===' -ForegroundColor Cyan
    $buildScript = Join-Path $repoRoot 'scripts/build.sh'
    & zsh $buildScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BUILD FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
        exit 2
    }
}

Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop
Write-Host ("=== Pester {0} ===" -f (Get-Module Pester).Version) -ForegroundColor Cyan

$config = New-PesterConfiguration
$config.Run.Path = $(if ($Path) { $Path } else { $testRoot })
$config.Run.PassThru = $true
$config.Run.Exit = $false
$config.Output.Verbosity = 'Detailed'
$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'NUnitXml'
$config.TestResult.OutputPath = Join-Path $buildDir 'test-results.xml'
$config.Should.ErrorAction = 'Stop'

$result = Invoke-Pester -Configuration $config

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
Write-Host ("Total   : {0}" -f $result.TotalCount)
Write-Host ("Passed  : {0}" -f $result.PassedCount)
Write-Host ("Failed  : {0}" -f $result.FailedCount)
Write-Host ("Skipped : {0}" -f $result.SkippedCount)
Write-Host ("Results : {0}" -f $config.TestResult.OutputPath.Value)

if ($result.FailedCount -gt 0) {
    Write-Host ("FAILED: {0} test(s) failed." -f $result.FailedCount) -ForegroundColor Red
    exit 1
}

if ($result.TotalCount -lt $MinimumTests) {
    Write-Host ("FAILED: only {0} test(s) ran, expected at least {1}. Test discovery is broken." -f
        $result.TotalCount, $MinimumTests) -ForegroundColor Red
    exit 3
}

Write-Host 'PASSED' -ForegroundColor Green
exit 0
