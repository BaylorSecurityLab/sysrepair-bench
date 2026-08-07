# Verification script for Scenario 15: WordPress 4.7.1 + admin:admin
# Two-component verdict: poc = the default admin:admin path is closed;
# regression = the WordPress install is still there and still serving.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$base = 'http://localhost'

###############################################################################
# Regression Check: the WordPress tree must still be installed. version.php is
# the canonical marker; its absence means WordPress was deleted, not fixed.
# (The v1 script labelled this [Regression] and exited immediately, which also
# meant the PoC component was never measured on a deleted install.)
###############################################################################
$verFile = 'C:\wamp\www\wordpress\wp-includes\version.php'
$verFilePresent = Test-Path $verFile
if ($verFilePresent) { Record-Reg wordpress_files_present 1 }
else { Record-Reg wordpress_files_present 0 "WordPress version.php not found ($verFile)." }

###############################################################################
# PoC Check: WordPress version must be >= 4.7.2 OR the admin:admin login no
# longer works. Either condition closes the critical path.
###############################################################################
$versionFixed = $false
$ver = 'unknown'
if ($verFilePresent) {
    try {
        $content = Get-Content $verFile -Raw -ErrorAction Stop
        if ($content -match "\`$wp_version\s*=\s*'([^']+)'") {
            $ver = $matches[1]
            # @() is load-bearing. Without it a single-component version ("5")
            # leaves $parts a SCALAR int, and `$parts += 0` on a scalar is
            # arithmetic (5 + 0 = 5), not an append -- .Count stays 1 and the
            # loop below never terminates. The verifier hangs forever, emits no
            # summary, and the sample is lost. Same for a version with no
            # numeric component at all, where $parts would be $null.
            $parts = @($ver.Split('.-') | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
            while ($parts.Count -lt 3) { $parts += 0 }
            if ($parts[0] -gt 4 -or
               ($parts[0] -eq 4 -and $parts[1] -gt 7) -or
               ($parts[0] -eq 4 -and $parts[1] -eq 7 -and $parts[2] -ge 2)) {
                $versionFixed = $true
            }
        }
    } catch {
        Write-Host "INFO [PoC]: could not read $verFile ($($_.Exception.Message)); falling back to the credential probe."
    }
}

if ($versionFixed) {
    Record-Poc wp_default_admin_creds_closed 1 "WordPress version $ver >= 4.7.2."
} else {
    # Live login attempt with admin:admin against wp-login.php
    $body = @{ log = 'admin'; pwd = 'admin'; 'wp-submit' = 'Log In'; redirect_to = "$base/wp-admin/"; testcookie = '1' }
    $session = $null
    try {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        # Seed the test cookie WordPress requires
        $session.Cookies.Add((New-Object System.Net.Cookie('wordpress_test_cookie','WP+Cookie+check','/','localhost')))
        $resp = Invoke-WebRequest -Uri "$base/wp-login.php" -Method POST -Body $body `
            -WebSession $session -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 8 -ErrorAction SilentlyContinue
    } catch {
        $resp = $_.Exception.Response
    }
    $loginSucceeded = $false
    try {
        if ($session -and $session.Cookies) {
            foreach ($c in $session.Cookies.GetCookies("$base/")) {
                if ($c.Name -like 'wordpress_logged_in*') { $loginSucceeded = $true }
            }
        }
    } catch { }
    if ($loginSucceeded) {
        Record-Poc wp_default_admin_creds_closed 0 "admin:admin still authenticates to /wp-login.php (version $ver)."
    } else {
        Record-Poc wp_default_admin_creds_closed 1 "admin:admin no longer authenticates (version $ver)."
    }
}

###############################################################################
# Regression Check: WordPress front page still serves HTTP 200 with WP markers.
# The IIS Default Web Site physicalPath is the WordPress tree itself, so WordPress
# is served at the site ROOT (http://localhost/), not under /wordpress/.
###############################################################################
$homeOk = $false
$homeDetail = ''
try {
    $wpHome = Invoke-WebRequest -Uri "$base/" -UseBasicParsing -TimeoutSec 8
    if ($wpHome.StatusCode -ne 200) {
        $homeDetail = "WordPress home returned HTTP $($wpHome.StatusCode)."
    } elseif ($wpHome.Content -notmatch 'wp-content|WordPress') {
        $homeDetail = 'WordPress home does not look like WordPress anymore.'
    } else {
        $homeOk = $true
    }
} catch {
    $homeDetail = "WordPress home unreachable ($($_.Exception.Message))."
}
if ($homeOk) { Record-Reg wordpress_home_serves 1 } else { Record-Reg wordpress_home_serves 0 $homeDetail }

Complete-Verify
