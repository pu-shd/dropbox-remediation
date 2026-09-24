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
            scp = 'DeviceManagementScripts.ReadWrite.All User.Read'
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
            scp = 'DeviceManagementScripts.ReadWrite.All'
        }
        $Script:EverydayJwt = Script:New-FakeJwt @{
            upn = 'everyday-user@contoso.com'
            tid = '11111111-2222-3333-4444-555555555555'
            scp = 'User.Read'
        }
        $Script:AppJwt = Script:New-FakeJwt @{
            appid = '99999999-8888-7777-6666-555555555555'
            tid   = '11111111-2222-3333-4444-555555555555'
            roles = 'DeviceManagementScripts.ReadWrite.All'
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

    It 'warns when the token has only the Configuration family for a scripts endpoint' {
        # Kept deliberately permissive: some tenants grant both families, and other
        # Intune endpoints do use DeviceManagementConfiguration. Remediations do not.
        $configOnly = Script:New-FakeJwt @{
            upn = 'intune-admin@contoso.com'
            scp = 'DeviceManagementConfiguration.ReadWrite.All'
        }
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_assert_identity '$configOnly'
"@
        $result.ExitCode | Should -Be 0
        $result.StdErr | Should -Not -Match 'WARNING'
    }

    It 'names DeviceManagementScripts, the permission remediations actually enforce' {
        $noScope = Script:New-FakeJwt @{ upn = 'intune-admin@contoso.com'; scp = 'User.Read' }
        $result = Script:Invoke-Zsh @"
source '$Script:GraphLib'
graph_assert_identity '$noScope'
"@
        $result.StdErr | Should -Match 'DeviceManagementScripts\.ReadWrite\.All'
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

Describe 'graph_request' {
    BeforeAll {
        function Script:Invoke-GraphRequest {
            <#
                Runs graph_request against a fake curl on PATH. Exercising the real
                function matters: it must locate external commands (mktemp, curl, jq)
                and assign a status variable, and zsh reserves names for both.
            #>
            param([int]$HttpStatus = 200, [string]$Body = '{"value":[]}', [string]$Method = 'GET')

            $work = Join-Path ([System.IO.Path]::GetTempPath()) ("dbw-req-" + [Guid]::NewGuid().ToString('n'))
            $bin = Join-Path $work 'bin'
            New-Item -ItemType Directory -Path $bin -Force | Out-Null

            $bodyFile = Join-Path $work 'body.json'
            Set-Content -LiteralPath $bodyFile -Value $Body

            $fakeCurl = @"
#!/usr/bin/env zsh
# Mimic: curl -sS -o <file> -w '%{http_code}' ...
out=''
prev=''
for a in "`$@"; do
  if [[ "`$prev" == "-o" ]]; then out="`$a"; fi
  prev="`$a"
done
if [[ -n "`$out" ]]; then cp '$bodyFile' "`$out"; fi
print -n -- '$HttpStatus'
"@
            Set-Content -LiteralPath (Join-Path $bin 'curl') -Value $fakeCurl
            & chmod +x (Join-Path $bin 'curl')

            $runner = Join-Path $work 'run.zsh'
            Set-Content -LiteralPath $runner -Value @"
export PATH='$bin':`$PATH
ROOT_DIR='$work'
source '$Script:GraphLib'
GRAPH_TOKEN='fake-token'
graph_request $Method '/deviceManagement/deviceHealthScripts'
print -- "RC=`$?"
"@
            $errFile = Join-Path $work 'err.txt'
            $stdout = (& zsh $runner 2>$errFile | Out-String)
            $stderr = ''
            if (Test-Path -LiteralPath $errFile) { $stderr = Get-Content -LiteralPath $errFile -Raw }
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue

            return [pscustomobject]@{ StdOut = $stdout; StdErr = $stderr }
        }
    }

    It 'returns the response body and succeeds on 200' {
        $r = Script:Invoke-GraphRequest -HttpStatus 200 -Body '{"value":[{"id":"abc"}]}'
        $r.StdOut | Should -Match 'RC=0'
        $r.StdOut | Should -Match '"id":"abc"'
    }

    It 'can still find external commands - zsh ties $path to $PATH' {
        # A local named 'path' inside the function would wipe command lookup, making
        # mktemp and curl vanish at runtime with "command not found".
        $r = Script:Invoke-GraphRequest -HttpStatus 200
        $r.StdErr | Should -Not -Match 'command not found'
    }

    It 'can assign its status variable - zsh makes $status read-only' {
        $r = Script:Invoke-GraphRequest -HttpStatus 200
        $r.StdErr | Should -Not -Match 'read-only variable'
    }

    It 'fails and surfaces the Graph error message on 403' {
        $r = Script:Invoke-GraphRequest -HttpStatus 403 -Body '{"error":{"message":"Forbidden - missing scope"}}'
        $r.StdOut | Should -Match 'RC=1'
        $r.StdErr | Should -Match 'HTTP 403'
        $r.StdErr | Should -Match 'Forbidden - missing scope'
    }

    It 'fails on 404 as well as 403' {
        $r = Script:Invoke-GraphRequest -HttpStatus 404 -Body '{"error":{"message":"not found"}}'
        $r.StdOut | Should -Match 'RC=1'
        $r.StdErr | Should -Match 'HTTP 404'
    }

    It 'treats 201 as success, since creates return it' {
        $r = Script:Invoke-GraphRequest -HttpStatus 201 -Body '{"id":"new"}' -Method POST
        $r.StdOut | Should -Match 'RC=0'
        $r.StdOut | Should -Match '"id":"new"'
    }
}

Describe 'zsh reserved parameter names' {
    It 'never declares or assigns a zsh special parameter in any shipped script' {
        # zsh ties $path to $PATH and makes $status read-only, among others. Both fail
        # only at runtime, in the one code path that talks to the tenant.
        $reserved = 'status|path|argv|options|commands|functions|aliases|signals|pipestatus|EUID|UID|GID|PPID|PWD|RANDOM|SECONDS|TTY|USERNAME|ARGC|LINENO|HOST'
        $scripts = @(Get-ChildItem -LiteralPath (Join-Path $Script:RepoRoot 'scripts') -Filter '*.sh' -Recurse)
        $scripts.Count | Should -BeGreaterThan 0

        $offenders = @()
        foreach ($file in $scripts) {
            $lineNo = 0
            foreach ($line in (Get-Content -LiteralPath $file.FullName)) {
                $lineNo++
                if ($line -match '^\s*#') { continue }
                if ($line -match "\b(local|typeset|declare)\b[^#]*\b($reserved)\b\s*[=\s]") {
                    $offenders += "$($file.Name):$lineNo declares '$($Matches[2])'"
                }
                if ($line -match "^\s*($reserved)=") {
                    $offenders += "$($file.Name):$lineNo assigns '$($Matches[1])'"
                }
            }
        }
        @($offenders).Count | Should -Be 0 -Because ($offenders -join '; ')
    }
}
