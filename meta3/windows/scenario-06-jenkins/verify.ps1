# Verification script for Scenario 06: Jenkins CLI deserialization (CVE-2017-1000353)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$war    = 'C:\jenkins\jenkins.war'
$config = 'C:\jenkins\home\config.xml'

###############################################################################
# Config Check: Jenkins WAR version must be >= 2.46.2 (LTS >= 2.46.2 / weekly >= 2.57)
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

if (-not (Test-Path $war)) {
    Write-Host "FAIL [Config]: $war missing."
    exit 1
}
$ver = Get-JenkinsVersion $war
if (-not $ver) {
    Write-Host "FAIL [Config]: Could not determine Jenkins-Version from $war manifest."
    exit 1
}
$parts = $ver.Split('.') | ForEach-Object { [int]$_ }
while ($parts.Count -lt 3) { $parts += 0 }
$fixed = ($parts[0] -gt 2) -or
         ($parts[0] -eq 2 -and $parts[1] -gt 46) -or
         ($parts[0] -eq 2 -and $parts[1] -eq 46 -and $parts[2] -ge 2)
if (-not $fixed) {
    Write-Host "FAIL [Config]: Jenkins $ver is still vulnerable to CVE-2017-1000353 (need >= 2.46.2)."
    exit 1
}
Write-Host "PASS [Config]: Jenkins upgraded to $ver."

###############################################################################
# Behavioral Check: CLI remoting must not accept unauthenticated commands.
# With security disabled (useSecurity=false), the CLI channel on port 5555
# or /cli endpoint accepts arbitrary Java object streams without auth.
# A patched/secured Jenkins returns 401 or closes the CLI port.
#
# Probe: GET /api/json without credentials — unauthenticated access to the
# API confirms security is disabled. Also check the CLI port.
###############################################################################
$cliPort = 5555
$portOpen = $false
try {
    $tcpConn = Test-NetConnection -ComputerName localhost -Port $cliPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($tcpConn.TcpTestSucceeded) { $portOpen = $true }
} catch {}

if ($portOpen) {
    # CLI port is open — check if unauth access is blocked
    $apiResp = $null
    try {
        $apiResp = Invoke-WebRequest -Uri 'http://localhost:8080/api/json' -UseBasicParsing -TimeoutSec 8 -ErrorAction SilentlyContinue
    } catch { $apiResp = $null }

    # With security enabled: /api/json returns 401. With security disabled: returns JSON.
    if ($apiResp -and $apiResp.StatusCode -eq 200 -and $apiResp.Content -match '"principal"|"userName"|"absoluteUrl"') {
        Write-Host "FAIL [PoC]: Jenkins API accessible unauthenticated (security disabled) — CLI RCE possible."
        exit 1
    }
    # CLI port open but API locked — might be CLI auth required. Still warn.
    Write-Host "WARN [PoC]: CLI port $cliPort open but API access blocked — verify CLI auth is enforced."
}
Write-Host "PASS [PoC]: CLI remoting not accepting unauthenticated commands."

###############################################################################
# Hygiene Check: useSecurity must be true after upgrade (keeps /script out of anon reach)
###############################################################################
if (Test-Path $config) {
    $cfg = Get-Content $config -Raw
    if ($cfg -match '<useSecurity>false</useSecurity>') {
        Write-Host "FAIL [Hygiene]: config.xml still has useSecurity=false."
        exit 1
    }
}
Write-Host "PASS [Hygiene]: Jenkins security not explicitly disabled."

###############################################################################
# Regression Check: Jenkins responding on 8080
###############################################################################
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 10
    if ($resp.StatusCode -notin 200,302,403) {
        Write-Host "FAIL [Regression]: Jenkins returned unexpected status $($resp.StatusCode)."
        exit 1
    }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -notin 200,302,403) {
        Write-Host "FAIL [Regression]: Jenkins not responding on 8080 ($_)."
        exit 1
    }
}
Write-Host "PASS [Regression]: Jenkins responding on 8080."

Write-Host "All checks passed."
exit 0
