# Verification script for Scenario 15: WordPress 4.7.1 + admin:admin
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
$ErrorActionPreference = 'Stop'

$base = 'http://localhost'

###############################################################################
# PoC Check 1: WordPress version must be >= 4.7.2 OR the admin:admin login no
# longer works. Either condition closes the critical path.
###############################################################################
$versionFixed = $false
$verFile = 'C:\wamp\www\wordpress\wp-includes\version.php'
if (Test-Path $verFile) {
    $content = Get-Content $verFile -Raw
    if ($content -match "\`$wp_version\s*=\s*'([^']+)'") {
        $ver = $matches[1]
        $parts = $ver.Split('.-') | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
        while ($parts.Count -lt 3) { $parts += 0 }
        if ($parts[0] -gt 4 -or
           ($parts[0] -eq 4 -and $parts[1] -gt 7) -or
           ($parts[0] -eq 4 -and $parts[1] -eq 7 -and $parts[2] -ge 2)) {
            $versionFixed = $true
            Write-Host "PASS [PoC]: WordPress version $ver >= 4.7.2."
        } else {
            Write-Host "INFO [PoC]: WordPress version $ver is still < 4.7.2; checking credentials."
        }
    }
} else {
    Write-Host "FAIL [Regression]: WordPress version.php not found."
    exit 1
}

if (-not $versionFixed) {
    # Live login attempt with admin:admin against wp-login.php
    $body = @{ log = 'admin'; pwd = 'admin'; 'wp-submit' = 'Log In'; redirect_to = "$base/wordpress/wp-admin/"; testcookie = '1' }
    try {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        # Seed the test cookie WordPress requires
        $session.Cookies.Add((New-Object System.Net.Cookie('wordpress_test_cookie','WP+Cookie+check','/','localhost')))
        $resp = Invoke-WebRequest -Uri "$base/wordpress/wp-login.php" -Method POST -Body $body `
            -WebSession $session -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 8 -ErrorAction SilentlyContinue
    } catch {
        $resp = $_.Exception.Response
    }
    $loginSucceeded = $false
    if ($session -and $session.Cookies) {
        foreach ($c in $session.Cookies.GetCookies("$base/wordpress/").Cast[System.Net.Cookie]()) {
            if ($c.Name -like 'wordpress_logged_in*') { $loginSucceeded = $true }
        }
    }
    if ($loginSucceeded) {
        Write-Host "FAIL [PoC]: admin:admin still authenticates to /wp-login.php."
        exit 1
    }
    Write-Host "PASS [PoC]: admin:admin no longer authenticates."
}

###############################################################################
# Regression Check: WordPress front page still serves HTTP 200 with WP markers
###############################################################################
try {
    $home = Invoke-WebRequest -Uri "$base/wordpress/" -UseBasicParsing -TimeoutSec 8
    if ($home.StatusCode -ne 200) {
        Write-Host "FAIL [Regression]: WordPress home returned HTTP $($home.StatusCode)."
        exit 1
    }
    if ($home.Content -notmatch 'wp-content|WordPress') {
        Write-Host "FAIL [Regression]: WordPress home does not look like WordPress anymore."
        exit 1
    }
} catch {
    Write-Host "FAIL [Regression]: WordPress home unreachable ($_)."
    exit 1
}
Write-Host "PASS [Regression]: WordPress still serves on port 80."

Write-Host "All checks passed."
exit 0
