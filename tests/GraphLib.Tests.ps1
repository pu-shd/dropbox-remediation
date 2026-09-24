#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Tests for scripts/lib/graph.sh - the identity handling that stands between a
    keystroke and a change to the tenant.

    The important behaviour here is negative: when the wrong account is signed in, the
    deploy scripts must STOP. These run the real zsh functions in a subshell and assert
    on exit codes, so a guard that silently passes fails the suite.
#>

BeforeAll {
    $Script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $Script:GraphLib = Join-Path $Script:RepoRoot 'scripts/lib/graph.sh'

    function Script:New-FakeJwt {
        <# An unsigned JWT with the given payload claims. #>
        param([hashtable]$Claims)
        $encode = {
            param($object)
            $json = $object | ConvertTo-Json -Compress -Depth 5
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)).
                TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }
        $header = & $encode @{ alg = 'none'; typ = 'JWT' }
        $payload = & $encode $Claims
        return "$header.$payload.signature"
    }

    function Script:Invoke-Zsh {
        <# Runs a zsh snippet and returns its stdout, stderr and exit code. #>
        param([string]$Script)
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-" + [Guid]::NewGuid().ToString('n') + ".zsh")
        $errFile = "$file.err"
        Set-Content -LiteralPath $file -Value $Script -Encoding UTF8
        try {
            $stdout = & zsh $file 2>$errFile
            $code = $LASTEXITCODE
            $stderr = ''
            if (Test-Path -LiteralPath $errFile) { $stderr = (Get-Content -LiteralPath $errFile -Raw) }
            return [pscustomobject]@{
                ExitCode = $code
                StdOut   = ($stdout | Out-String)
                StdErr   = $stderr
            }
        } finally {
            Remove-Item -LiteralPath $file, $errFile -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'graph_b64url_decode' {
    It 'decodes base64url with URL-safe characters and missing padding' {
        # '?>?>' encodes to bytes that produce both '-' and '_' in base64url.
        $raw = [Text.Encoding]::UTF8.GetBytes('~~~??>>>')
        $b64url = [Convert]::ToBase64String($raw).TrimEnd('=').Replace('+', '-').Replace('/', '_')

        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_b64url_decode '$b64url'
"@
        $result.ExitCode | Should -Be 0
        $result.StdOut.TrimEnd("`n") | Should -Be '~~~??>>>'
    }
}

Describe 'graph_jwt_claim' {
    BeforeAll {
        $Script:UserJwt = Script:New-FakeJwt @{
            upn = 'intune-admin@contoso.com'
            tid = '11111111-2222-3333-4444-555555555555'
            scp = 'DeviceManagementConfiguration.ReadWrite.All User.Read'
        }
    }

    It 'extracts a claim from the token payload' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_jwt_claim '$Script:UserJwt' upn
"@
        $result.StdOut.Trim() | Should -Be 'intune-admin@contoso.com'
    }

    It 'returns empty for a claim that is not present' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_jwt_claim '$Script:UserJwt' roles
"@
        $result.StdOut.Trim() | Should -BeNullOrEmpty
    }

    It 'returns empty rather than failing on a malformed token' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_jwt_claim 'not-a-jwt' upn
echo "survived"
"@
        $result.StdOut | Should -Match 'survived'
    }
}

Describe 'graph_assert_identity' {
    BeforeAll {
        $Script:IntuneJwt = Script:New-FakeJwt @{
            upn = 'intune-admin@contoso.com'
            tid = '11111111-2222-3333-4444-555555555555'
            scp = 'DeviceManagementConfiguration.ReadWrite.All'
        }
        $Script:EverydayJwt = Script:New-FakeJwt @{
            upn = 'everyday-user@contoso.com'
            tid = '11111111-2222-3333-4444-555555555555'
            scp = 'User.Read'
        }
        $Script:AppJwt = Script:New-FakeJwt @{
            appid = '99999999-8888-7777-6666-555555555555'
            tid   = '11111111-2222-3333-4444-555555555555'
            roles = 'DeviceManagementConfiguration.ReadWrite.All'
        }
    }

    It 'reports which account is about to make changes' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_assert_identity '$Script:IntuneJwt'
"@
        $result.ExitCode | Should -Be 0
        $result.StdOut | Should -Match 'acting as: intune-admin@contoso\.com'
        $result.StdOut | Should -Match '11111111-2222-3333-4444-555555555555'
    }

    It 'allows the expected account through' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
export DBW_EXPECT_UPN='intune-admin@contoso.com'
graph_assert_identity '$Script:IntuneJwt'
"@
        $result.ExitCode | Should -Be 0
    }

    It 'ignores case when comparing the account' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
export DBW_EXPECT_UPN='INTUNE-ADMIN@Contoso.COM'
graph_assert_identity '$Script:IntuneJwt'
"@
        $result.ExitCode | Should -Be 0
    }

    It 'refuses to continue when the everyday account is signed in instead' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
export DBW_EXPECT_UPN='intune-admin@contoso.com'
graph_assert_identity '$Script:EverydayJwt'
echo 'REACHED THE DEPLOY'
"@
        $result.ExitCode | Should -Not -Be 0
        $result.StdOut | Should -Not -Match 'REACHED THE DEPLOY'
        $result.StdErr | Should -Match 'signed in as everyday-user@contoso\.com'
        $result.StdErr | Should -Match 'expected intune-admin@contoso\.com'
    }

    It 'refuses an app token when a specific user account is required' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
export DBW_EXPECT_UPN='intune-admin@contoso.com'
graph_assert_identity '$Script:AppJwt'
echo 'REACHED THE DEPLOY'
"@
        $result.ExitCode | Should -Not -Be 0
        $result.StdOut | Should -Not -Match 'REACHED THE DEPLOY'
    }

    It 'accepts an app registration when no user account is pinned' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_assert_identity '$Script:AppJwt'
"@
        $result.ExitCode | Should -Be 0
        $result.StdOut | Should -Match 'app registration 99999999'
    }

    It 'warns when the token cannot manage Intune, before anything is sent' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_assert_identity '$Script:EverydayJwt'
"@
        $result.ExitCode | Should -Be 0
        $result.StdErr | Should -Match 'WARNING'
        $result.StdErr | Should -Match '403'
    }

    It 'does not warn when the token carries the Intune scope' {
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_assert_identity '$Script:IntuneJwt'
"@
        $result.StdErr | Should -Not -Match 'WARNING'
    }
}

Describe 'Azure CLI profile isolation' {
    It 'routes az through the dedicated profile when one is configured' {
        $result = Script:Invoke-Zsh @"
fake=`$(mktemp -d)
cat > "`$fake/az" <<'AZ'
#!/usr/bin/env zsh
print -- "AZURE_CONFIG_DIR=`${AZURE_CONFIG_DIR:-<unset>}"
AZ
chmod +x "`$fake/az"
export PATH="`$fake:`$PATH"
source '$Script:GraphLib'
export DBW_AZURE_CONFIG_DIR='/tmp/intune-profile'
graph_az account show
rm -rf "`$fake"
"@
        $result.StdOut | Should -Match 'AZURE_CONFIG_DIR=/tmp/intune-profile'
    }

    It 'leaves the default az profile alone when none is configured' {
        $result = Script:Invoke-Zsh @"
fake=`$(mktemp -d)
cat > "`$fake/az" <<'AZ'
#!/usr/bin/env zsh
print -- "AZURE_CONFIG_DIR=`${AZURE_CONFIG_DIR:-<unset>}"
AZ
chmod +x "`$fake/az"
export PATH="`$fake:`$PATH"
unset AZURE_CONFIG_DIR
source '$Script:GraphLib'
unset DBW_AZURE_CONFIG_DIR
graph_az account show
rm -rf "`$fake"
"@
        $result.StdOut | Should -Match 'AZURE_CONFIG_DIR=<unset>'
    }
}

Describe 'Per-checkout configuration' {
    It 'picks up .dbw.env from the repo root so the identity cannot be forgotten' {
        $result = Script:Invoke-Zsh @"
root=`$(mktemp -d)
cat > "`$root/.dbw.env" <<'ENV'
export DBW_EXPECT_UPN="intune-admin@contoso.com"
export DBW_AZURE_CONFIG_DIR="/tmp/from-env-file"
ENV
ROOT_DIR="`$root"
source '$Script:GraphLib'
print -- "upn=`${DBW_EXPECT_UPN:-<unset>} profile=`${DBW_AZURE_CONFIG_DIR:-<unset>}"
rm -rf "`$root"
"@
        $result.StdOut | Should -Match 'upn=intune-admin@contoso\.com'
        $result.StdOut | Should -Match 'profile=/tmp/from-env-file'
    }

    It 'works normally when no .dbw.env is present' {
        $result = Script:Invoke-Zsh @"
root=`$(mktemp -d)
ROOT_DIR="`$root"
source '$Script:GraphLib'
print -- "ok upn=`${DBW_EXPECT_UPN:-<unset>}"
rm -rf "`$root"
"@
        $result.ExitCode | Should -Be 0
        $result.StdOut | Should -Match 'ok upn=<unset>'
    }
}
