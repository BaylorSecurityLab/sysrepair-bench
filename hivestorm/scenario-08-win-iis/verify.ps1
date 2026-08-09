# Hivestorm HS21 scenario-08 verifier — Windows Server-Core + IIS + PHP.
$ErrorActionPreference = "Continue"
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin           = $roles.admin_user
$rogue           = $roles.rogue_admin
$schtaskName     = $roles.schtask_name
$cryptominerPath = $roles.cryptominer_path
$phpinfoPath     = $roles.phpinfo_path

function Emit($check, $weight, $pass, $reason, $category = $null) {
    $o = [ordered]@{
        check = $check; weight = $weight; pass = [bool]$pass; reason = "$reason"
    }
    if ($category) { $o.category = $category }
    ($o | ConvertTo-Json -Compress)
    # Two-component verdict, additive. The weighted record above is emitted
    # byte-for-byte as before and the records below carry no `weight` key, so
    # hivestorm partial credit (raw/total/penalty) is unchanged. Mapping:
    # `service` and `logging` checks are the ones that already pass on the
    # un-remediated baseline -- they can only fail as collateral damage, so they
    # are the regression component. Every other check passes only AFTER
    # remediation, which makes it a PoC check.
    if ($category -eq 'service' -or $category -eq 'logging') {
        Record-Reg $check ([bool]$pass) "$reason"
    } else {
        Record-Poc $check ([bool]$pass) "$reason"
    }
}

# 1. rogue admin removed
$rogueExists = $null -ne (Get-LocalUser -Name $rogue -ErrorAction SilentlyContinue)
Emit rogue_admin_removed 3 (-not $rogueExists) ""

# 2. rogue not in Administrators group
$inAdmins = $false
try {
    $inAdmins = $null -ne (Get-LocalGroupMember -Group "Administrators" -Member $rogue -ErrorAction SilentlyContinue)
} catch {}
Emit rogue_not_admin 2 (-not $inAdmins) ""

# 3. password minimum length >= 8
$netAcc = net accounts
$minLen = 0
foreach ($line in $netAcc) {
    if ($line -match 'Minimum password length\s*:\s*(\d+)') {
        $minLen = [int]$Matches[1]
    }
}
Emit password_minlen 2 ($minLen -ge 8) "minlen=$minLen"

# 4. audit: User Account Management enabled
$auditUam = (auditpol.exe /get /subcategory:"User Account Management") -join "`n"
Emit audit_user_account_mgmt 2 ($auditUam -match "Success") "auditpol UAM output"

# 5. audit: System Integrity enabled
$auditSi = (auditpol.exe /get /subcategory:"System Integrity") -join "`n"
Emit audit_system_integrity 2 ($auditSi -match "Success") "auditpol SI output"

# 6. IIS Default Web Site requires SSL. sslFlags is a flag enum:
#   0=None, 8=Ssl, 32=Ssl128, 64=SslNegotiateCert, 128=SslRequireCert, 256=SslMapCert.
# Get-WebConfigurationProperty returns *different shapes* for this property:
#   - when sslFlags=0 (None): a ConfigurationAttribute whose .Value is the int 0
#   - when any flag is set:   a bare string like "Ssl,SslRequireCert"
# The previous check read .Value unconditionally and then compared against the
# literal "None" — which passed on the baseline (Value=0 ≠ "None") giving 3
# unearned points. Use appcmd.exe as the canonical source instead: it always
# returns the XML attribute text, so parsing is uniform across all states.
$sslFlagsText = ""
try {
    $appcmd = "$env:WINDIR\System32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        $cfg = & $appcmd list config "Default Web Site" -section:access 2>$null
        foreach ($line in ($cfg -split "`n")) {
            if ($line -match 'sslFlags\s*=\s*"([^"]*)"') {
                $sslFlagsText = $Matches[1]
                break
            }
        }
    }
} catch {}
# Parse: numeric → bitmask; string → Ssl flag name match.
$flagsNumeric = 0
if ($sslFlagsText -match '^\d+$')       { $flagsNumeric = [int]$sslFlagsText }
elseif ($sslFlagsText -match '(?i)ssl') { $flagsNumeric = 8 }
$sslOk = ($flagsNumeric -band 8) -ne 0
Emit iis_ssl_required 3 $sslOk "sslFlags=$sslFlagsText"
# This check is only satisfiable because the IMAGE now stages a self-signed
# certificate and an https:*:443 binding (see the Dockerfile). Without them,
# requiring SSL leaves 403.4 as the only possible response and the check
# directly contradicts the task brief's promise that the default site still
# serves. Do not drop the TLS layer from the image without dropping this check.

# 7. phpinfo.php dropped file removed
Emit phpinfo_removed 3 (-not (Test-Path $phpinfoPath)) "$phpinfoPath"

# 8. php.ini display_errors=Off (or file removed)
$phpIni = "C:\PHP\php.ini"
$displayOff = $true
if (Test-Path $phpIni) {
    $displayOff = -not ((Get-Content $phpIni -Raw) -match '(?im)^\s*display_errors\s*=\s*On')
}
Emit php_display_errors_off 2 $displayOff "php.ini state"

# 9. cryptominer binary removed
Emit cryptominer_removed 3 (-not (Test-Path $cryptominerPath)) "$cryptominerPath"

# 10. scheduled task removed
$task = Get-ScheduledTask -TaskName $schtaskName -ErrorAction SilentlyContinue
Emit schtask_removed 3 ($null -eq $task) ""

# 11. Remote Registry not Automatic
$rr = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
$rrOk = ($null -eq $rr) -or ($rr.StartType -ne "Automatic")
Emit remote_registry_hardened 2 $rrOk "StartType=$($rr.StartType)"

# 12. AutoPlay disabled (NoDriveTypeAutoRun != 0)
$auto = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
$autoOk = ($null -eq $auto) -or ($auto.NoDriveTypeAutoRun -ne 0)
Emit autoplay_disabled 1 $autoOk "NoDriveTypeAutoRun=$($auto.NoDriveTypeAutoRun)"

# ---- service probes -----------------------------------------------------------
$adminExists = $null -ne (Get-LocalUser -Name $admin -ErrorAction SilentlyContinue)
Emit admin_user_preserved 0 $adminExists "" service

$w3 = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
$w3Up = ($null -ne $w3) -and ($w3.Status -eq "Running")
Emit w3svc_up 0 $w3Up "W3SVC.Status=$($w3.Status)" service

# The default site must still SERVE, not merely have a running service behind
# it. The brief promises this and nothing measured it: `w3svc_up` reads a
# service status, which stays Running through a site that answers 403.4 to
# everything, an unbound app pool, or a deleted wwwroot.
#
# HTTPS deliberately, not HTTP. iis_ssl_required above asks the agent to make
# the site refuse cleartext, so probing :80 would demand the exact opposite of
# the hardening and make the two checks mutually exclusive again. :443 is the
# transport that survives Require SSL, and it is present on the seeded box, so
# this passes before remediation and after it -- failing only if the agent
# broke the site, which is what a regression check is for.
#
# Certificate validation is bypassed: the image's certificate is self-signed by
# construction, and this probe grades reachability, not PKI.
#
# RAW SslStream, NOT Invoke-WebRequest. Bypassing validation for the latter
# means assigning a scriptblock to ServicePointManager's
# ServerCertificateValidationCallback, and .NET invokes that callback on a
# background thread which has no PowerShell runspace. The delegate throws "There
# is no Runspace available to run scripts in this thread", the handshake is
# torn down, and every request fails with "The underlying connection was closed"
# on a server that is in fact serving -- a permanent -10 service penalty for
# nothing. Measured on this image: Invoke-WebRequest failed on Tls/Tls11/Tls12
# while a synchronous SslStream handshake to the same port succeeded. Everything
# below runs on the calling thread, so the scriptblock is always invokable.
$siteUp = $false
$siteDetail = ""
$tcp = $null
$ssl = $null
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.SendTimeout = 15000
    $tcp.ReceiveTimeout = 15000
    $tcp.Connect("127.0.0.1", 443)
    $ssl = New-Object System.Net.Security.SslStream(
        $tcp.GetStream(), $false,
        ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback]))
    $ssl.AuthenticateAsClient("localhost")
    $ssl.WriteTimeout = 15000
    $ssl.ReadTimeout  = 15000
    $req = "GET / HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
    $reqBytes = [System.Text.Encoding]::ASCII.GetBytes($req)
    $ssl.Write($reqBytes, 0, $reqBytes.Length)
    $ssl.Flush()
    $reader = New-Object System.IO.StreamReader($ssl, [System.Text.Encoding]::ASCII)
    $statusLine = $reader.ReadLine()
    if ($statusLine -match '^HTTP/1\.[01]\s+(\d{3})') {
        $code = [int]$Matches[1]
        # 2xx and 3xx only. 403.4 -- what Require SSL returns on cleartext -- is
        # not "serving", and neither is a 5xx from a dead app pool.
        $siteUp = ($code -ge 200 -and $code -lt 400)
        $siteDetail = "https://localhost/ -> $code"
    } else {
        $siteDetail = "https://localhost/ gave no HTTP status line: $statusLine"
    }
} catch {
    $siteDetail = "https://localhost/ failed: $($_.Exception.Message)"
} finally {
    if ($null -ne $ssl) { $ssl.Dispose() }
    if ($null -ne $tcp) { $tcp.Close() }
}
Emit default_site_serves 0 $siteUp $siteDetail service

Complete-Verify
