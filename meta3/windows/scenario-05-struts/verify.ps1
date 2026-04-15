# Verification script for Scenario 05: Apache Struts 2 S2-045 (CVE-2017-5638)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$webapp = 'C:\tomcat\webapps\struts2-rest-showcase'
$war    = 'C:\tomcat\webapps\struts2-rest-showcase.war'

###############################################################################
# PoC Check: app removed OR struts2-core upgraded to a fixed version
###############################################################################
$appPresent = (Test-Path $webapp) -or (Test-Path $war)
if (-not $appPresent) {
    Write-Host "PASS [PoC]: Vulnerable Struts Showcase app removed."
} else {
    $jar = Get-ChildItem -Path (Join-Path $webapp 'WEB-INF\lib') -Filter 'struts2-core-*.jar' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $jar) {
        Write-Host "FAIL [PoC]: Unable to locate struts2-core jar under WEB-INF\lib."
        exit 1
    }
    if ($jar.Name -match 'struts2-core-(?<v>\d+)\.(?<mj>\d+)\.(?<mn>\d+)(?:\.(?<p>\d+))?\.jar') {
        $v  = [int]$Matches.v
        $mj = [int]$Matches.mj
        $mn = [int]$Matches.mn
        # Fixed in 2.3.32 and 2.5.10.1
        $fixed =  ($v -gt 2) -or
                  ($v -eq 2 -and $mj -eq 3 -and $mn -ge 32) -or
                  ($v -eq 2 -and $mj -ge 5 -and $mn -ge 10)
        if (-not $fixed) {
            Write-Host "FAIL [PoC]: struts2-core $($jar.Name) is still S2-045-vulnerable (need >= 2.3.32 or >= 2.5.10.1)."
            exit 1
        }
        Write-Host "PASS [PoC]: struts2-core upgraded to $($jar.Name)."
    } else {
        Write-Host "FAIL [PoC]: Unrecognized struts2-core jar name: $($jar.Name)"
        exit 1
    }
}

###############################################################################
# Regression Check: Tomcat still responding on 8080
###############################################################################
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    if ($resp.StatusCode -notin 200,302,404) {
        Write-Host "FAIL [Regression]: Tomcat returned unexpected status $($resp.StatusCode)."
        exit 1
    }
} catch {
    Write-Host "FAIL [Regression]: Tomcat not responding on 8080 ($_)."
    exit 1
}
Write-Host "PASS [Regression]: Tomcat responding on 8080."

Write-Host "All checks passed."
exit 0
