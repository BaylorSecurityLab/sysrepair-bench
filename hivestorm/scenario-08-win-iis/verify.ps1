# Hivestorm HS21 scenario-08 verifier — Windows Server-Core + IIS + PHP.
$ErrorActionPreference = "Continue"

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

exit 0
