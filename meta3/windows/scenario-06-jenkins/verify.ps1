# Verification script for Scenario 06: Jenkins CLI deserialization (CVE-2017-1000353)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

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

if (-not (Test-Path $war)) {
    Write-Host "FAIL [PoC]: $war missing."
    exit 1
}
$ver = Get-JenkinsVersion $war
if (-not $ver) {
    Write-Host "FAIL [PoC]: Could not determine Jenkins-Version from $war manifest."
    exit 1
}
$parts = $ver.Split('.') | ForEach-Object { [int]$_ }
while ($parts.Count -lt 3) { $parts += 0 }
$fixed = ($parts[0] -gt 2) -or
         ($parts[0] -eq 2 -and $parts[1] -gt 46) -or
         ($parts[0] -eq 2 -and $parts[1] -eq 46 -and $parts[2] -ge 2)
if (-not $fixed) {
    Write-Host "FAIL [PoC]: Jenkins $ver is still vulnerable to CVE-2017-1000353 (need >= 2.46.2)."
    exit 1
}
Write-Host "PASS [PoC]: Jenkins upgraded to $ver."

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
