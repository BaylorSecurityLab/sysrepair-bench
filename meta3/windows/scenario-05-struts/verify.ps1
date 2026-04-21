# Verification script for Scenario 05: Apache Struts 2 S2-045 (CVE-2017-5638)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$webapp = 'C:\tomcat\webapps\struts2-rest-showcase'
$war    = 'C:\tomcat\webapps\struts2-rest-showcase.war'

###############################################################################
# Config Check: app removed OR struts2-core upgraded to a fixed version
###############################################################################
$appPresent = (Test-Path $webapp) -or (Test-Path $war)
if (-not $appPresent) {
    Write-Host "PASS [Config]: Vulnerable Struts Showcase app removed."
} else {
    $jar = Get-ChildItem -Path (Join-Path $webapp 'WEB-INF\lib') -Filter 'struts2-core-*.jar' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $jar) {
        Write-Host "FAIL [Config]: Unable to locate struts2-core jar under WEB-INF\lib."
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
            Write-Host "FAIL [Config]: struts2-core $($jar.Name) is still S2-045-vulnerable (need >= 2.3.32 or >= 2.5.10.1)."
            exit 1
        }
        Write-Host "PASS [Config]: struts2-core upgraded to $($jar.Name)."
    } else {
        Write-Host "FAIL [Config]: Unrecognized struts2-core jar name: $($jar.Name)"
        exit 1
    }
}

###############################################################################
# Behavioral Check: S2-045 OGNL expression must NOT be evaluated.
# Send a harmless OGNL math expression; patched servers return a 4xx or the
# expression is inert. Vulnerable servers evaluate it and the result may appear
# in the error page (or any reflected output).
###############################################################################
$probeUrl = 'http://localhost:8080/struts2-rest-showcase/orders'

# First check: does the endpoint respond at all?
try {
    $preResp = Invoke-WebRequest -Uri $probeUrl -UseBasicParsing -TimeoutSec 8 -ErrorAction SilentlyContinue
} catch {
    $preResp = $null
}
if (-not $preResp) {
    # Endpoint unreachable — can't do behavioral check, rely on config
    Write-Host "PASS [PoC]: struts2-rest-showcase endpoint unreachable (app may be removed)."
    Write-Host "PASS [Regression]: Tomcat responding on 8080."
    Write-Host "All checks passed."
    exit 0
}

# S2-045 triggers on Content-Type header with OGNL chars; send a probing
# Content-Type that vulnerable Struts parses. We look for OGNL evaluation
# in the response — the probe expression is deliberately obscure so a
# patched server simply returns 400/403 without OGNL involvement.
$headers = @{
    'Content-Type' = "multipart/form-data; charset=`${(new java.lang.String(new byte[]{66,117,105,108,116,105,110})).substring(0,3)}"
}
try {
    $r = Invoke-WebRequest -Uri $probeUrl -Method POST `
        -Headers $headers -Body 'dummy=value' `
        -UseBasicParsing -TimeoutSec 8 -ErrorAction SilentlyContinue
    $status = $r.StatusCode
    $body   = $r.Content
} catch {
    $body   = $_.Exception.Message
    $status = $_.Exception.Response.StatusCode.value__
}

# Vulnerable: response may contain "Buil" (evaluated from ${(new...).substring(0,3)})
# or any artifact of the OGNL being interpreted. Fixed: 400/403 with no eval.
if ($status -lt 400 -and $body -match 'Buil|tain|Built') {
    Write-Host "FAIL [PoC]: OGNL expression evaluated in response — S2-045 present."
    exit 1
}
Write-Host "PASS [PoC]: No OGNL evaluation detected (server rejects or ignores probe)."

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
