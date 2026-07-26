BeforeAll {
    . "$PSScriptRoot/../lab/Get-ScenarioToolPaths.ps1"
}

Describe 'Get-ScenarioToolPaths' {
    BeforeEach {
        $script:root = Join-Path $TestDrive 'scenarios'
        New-Item -ItemType Directory -Path (Join-Path $script:root 'scenario-99') -Force | Out-Null
    }

    It 'extracts an absolute tool path from a verify-poc.sh' {
        Set-Content -Path (Join-Path $script:root 'scenario-99/verify-poc.sh') -Value @'
#!/usr/bin/env bash
OUT=$(timeout 60 /usr/bin/impacket-GetUserSPNs -dc-ip 10.20.30.5 2>&1 || true)
'@
        $r = Get-ScenarioToolPaths -ScenarioRoot $script:root
        $r.Path | Should -Contain '/usr/bin/impacket-GetUserSPNs'
        $r[0].Scenario | Should -Be 'scenario-99'
    }

    It 'ignores the shebang line' {
        Set-Content -Path (Join-Path $script:root 'scenario-99/verify-poc.sh') -Value @'
#!/usr/bin/env bash
echo hello
'@
        $r = Get-ScenarioToolPaths -ScenarioRoot $script:root
        $r | Should -BeNullOrEmpty
    }

    It 'extracts a bare command checked with command -v' {
        Set-Content -Path (Join-Path $script:root 'scenario-99/verify-poc.sh') -Value @'
#!/usr/bin/env bash
if ! command -v xfreerdp >/dev/null 2>&1; then exit 0; fi
'@
        $r = Get-ScenarioToolPaths -ScenarioRoot $script:root
        $r.Path | Should -Contain 'xfreerdp'
    }

    It 'deduplicates repeated paths within one scenario' {
        Set-Content -Path (Join-Path $script:root 'scenario-99/verify-poc.sh') -Value @'
#!/usr/bin/env bash
/usr/bin/certipy-ad req
/usr/bin/certipy-ad auth
'@
        $r = Get-ScenarioToolPaths -ScenarioRoot $script:root
        @($r | Where-Object Path -eq '/usr/bin/certipy-ad').Count | Should -Be 1
    }

    It 'records the line number where the tool is first invoked' {
        Set-Content -Path (Join-Path $script:root 'scenario-99/verify-poc.sh') -Value @'
#!/usr/bin/env bash
set -euo pipefail
/usr/bin/impacket-secretsdump corp.local/alice@10.20.30.5
'@
        $r = Get-ScenarioToolPaths -ScenarioRoot $script:root
        ($r | Where-Object Path -eq '/usr/bin/impacket-secretsdump').Line | Should -Be 3
    }
}
