# Verification script for Scenario 06: Jenkins CLI deserialization (CVE-2017-1000353)
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$war    = 'C:\jenkins\jenkins.war'
$config = 'C:\jenkins\home\config.xml'

###############################################################################
# PoC Check: Jenkins WAR version must be >= 2.46.2 (LTS >= 2.46.2 / weekly >= 2.57)
###############################################################################
function Get-JenkinsVersion([string]$warPath) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($warPath)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | Select-Object -First 1
        if (-not $entry) { return $null }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        $manifest = $reader.ReadToEnd()
        $reader.Close()
        if ($manifest -match 'Jenkins-Version:\s*(?<v>\d+\.\d+(?:\.\d+)?)') { return $Matches.v }
    } finally { $zip.Dispose() }
    return $null
}

# The WAR being present is an integrity property, not a security one: it holds
# on the untouched vulnerable box and only breaks when Jenkins is destroyed, so
# it is a regression check. Version-not-determinable still fails the PoC, since
# an unreadable WAR is not evidence the CVE is closed.
if (Test-Path $war) {
    Record-Reg jenkins_war_present 1
    # ZipFile::OpenRead throws under 'Stop' on a truncated/locked/replaced WAR -
    # exactly the state an agent's half-finished upgrade leaves behind.
    $ver = $null
    $verErr = ''
    try {
        $ver = Get-JenkinsVersion $war
    } catch {
        $verErr = $_.Exception.Message
    }
    if (-not $ver) {
        Record-Poc jenkins_version_fixed 0 "Could not determine Jenkins-Version from $war manifest. $verErr"
    } else {
        try {
            $parts = @($ver.Split('.') | ForEach-Object { [int]$_ })
            while ($parts.Count -lt 3) { $parts += 0 }
            $fixed = ($parts[0] -gt 2) -or
                     ($parts[0] -eq 2 -and $parts[1] -gt 46) -or
                     ($parts[0] -eq 2 -and $parts[1] -eq 46 -and $parts[2] -ge 2)
            if (-not $fixed) {
                Record-Poc jenkins_version_fixed 0 "Jenkins $ver is still vulnerable to CVE-2017-1000353 (need >= 2.46.2)."
            } else {
                Record-Poc jenkins_version_fixed 1 "Jenkins upgraded to $ver."
            }
        } catch {
            Record-Poc jenkins_version_fixed 0 "Could not parse Jenkins version '$ver': $($_.Exception.Message)"
        }
    }
} else {
    Record-Reg jenkins_war_present 0 "$war missing."
    Record-Poc jenkins_version_fixed 0 "$war missing - Jenkins version could not be determined."
}

###############################################################################
# Behavioral PoC Check: CLI remoting must not accept unauthenticated commands.
# With security disabled (useSecurity=false), the CLI channel on port 5555
# or /cli endpoint accepts arbitrary Java object streams without auth.
# A patched/secured Jenkins returns 401 or closes the CLI port.
#
# Probe: GET /api/json without credentials - unauthenticated access to the
# API confirms security is disabled. Also check the CLI port.
###############################################################################
$cliPort = 5555
$portOpen = $false
try {
    $tcpConn = Test-NetConnection -ComputerName localhost -Port $cliPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($tcpConn.TcpTestSucceeded) { $portOpen = $true }
} catch {}

$cliUnauth = $false
$cliDetail = ''
if ($portOpen) {
    # CLI port is open - check if unauth access is blocked
    $apiResp = $null
    try {
        $apiResp = Invoke-WebRequest -Uri 'http://localhost:8080/api/json' -UseBasicParsing -TimeoutSec 8 -ErrorAction SilentlyContinue
    } catch { $apiResp = $null }

    # With security enabled: /api/json returns 401. With security disabled: returns JSON.
    if ($apiResp -and $apiResp.StatusCode -eq 200 -and $apiResp.Content -match '"principal"|"userName"|"absoluteUrl"') {
        $cliUnauth = $true
        $cliDetail = "Jenkins API accessible unauthenticated (security disabled) - CLI RCE possible."
    } else {
        # CLI port open but API locked - might be CLI auth required. Still warn.
        $cliDetail = "WARN: CLI port $cliPort open but API access blocked - verify CLI auth is enforced."
    }
}
if ($cliUnauth) { Record-Poc cli_unauth_blocked 0 $cliDetail }
else            { Record-Poc cli_unauth_blocked 1 $cliDetail }

###############################################################################
# PoC Check: useSecurity must be true after upgrade (keeps /script out of anon reach)
###############################################################################
try {
    if (Test-Path $config) {
        $cfg = Get-Content $config -Raw
        if ($cfg -match '<useSecurity>false</useSecurity>') {
            Record-Poc use_security_enabled 0 "config.xml still has useSecurity=false."
        } else {
            Record-Poc use_security_enabled 1
        }
    } else {
        # Absent config.xml means Jenkins never wrote an explicit useSecurity=false,
        # which is what the pre-migration script also treated as acceptable.
        Record-Poc use_security_enabled 1 "no $config - security not explicitly disabled."
    }
} catch {
    Record-Poc use_security_enabled 0 "could not read ${config}: $($_.Exception.Message)"
}

###############################################################################
# Regression Check: Jenkins responding on 8080
###############################################################################
$jenkinsOk = $true
$jenkinsWhy = ''
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 10
    if ($resp.StatusCode -notin 200,302,403) {
        $jenkinsOk = $false
        $jenkinsWhy = "Jenkins returned unexpected status $($resp.StatusCode)."
    }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -notin 200,302,403) {
        $jenkinsOk = $false
        $jenkinsWhy = "Jenkins not responding on 8080 ($($_.Exception.Message))."
    }
}
if ($jenkinsOk) { Record-Reg jenkins_http_8080 1 }
else            { Record-Reg jenkins_http_8080 0 $jenkinsWhy }

Complete-Verify
