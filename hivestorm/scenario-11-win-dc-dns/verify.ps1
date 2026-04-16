# Hivestorm HS23 scenario-11 verifier — DC/DNS-style registry hardening.
$ErrorActionPreference = "Continue"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin = $roles.admin_user
$rogue = $roles.rogue_admin

function Emit($check, $weight, $pass, $reason, $category = $null) {
    $o = [ordered]@{
        check = $check; weight = $weight; pass = [bool]$pass; reason = "$reason"
    }
    if ($category) { $o.category = $category }
    ($o | ConvertTo-Json -Compress)
}

function GetDword($path, $name) {
    try {
        return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
    } catch { return $null }
}

# 1. rogue admin removed
$rogueExists = $null -ne (Get-LocalUser -Name $rogue -ErrorAction SilentlyContinue)
Emit rogue_admin_removed 3 (-not $rogueExists) ""

# 2. rogue not in Administrators
$inAdmins = $false
try {
    $inAdmins = $null -ne (Get-LocalGroupMember -Group "Administrators" -Member $rogue -ErrorAction SilentlyContinue)
} catch {}
Emit rogue_not_admin 2 (-not $inAdmins) ""

# 3. LDAP server signing required (LDAPServerIntegrity = 2)
$ldap = GetDword "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
Emit ldap_signing_required 3 ($ldap -eq 2) "LDAPServerIntegrity=$ldap"

# 4. MS network client signing required
$mc = GetDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
Emit ms_network_client_signing 2 ($mc -eq 1) "RequireSecuritySignature=$mc"

# 5. Kerberos: only AES (no DES bits, no RC4 bit)
$kt = GetDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes"
$weakBits = 0
if ($null -ne $kt) {
    $weakBits = $kt -band 0x7   # DES_CRC | DES_MD5 | RC4_HMAC
}
$ktOk = ($null -ne $kt) -and ($weakBits -eq 0) -and (($kt -band 0x18) -ne 0)
Emit kerberos_aes_only 2 $ktOk "SupportedEncryptionTypes=$kt"

# 6. LLMNR off (EnableMulticast = 0)
$llmnr = GetDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
Emit llmnr_off 2 ($llmnr -eq 0) "EnableMulticast=$llmnr"

# 7. DNS Server: SecureResponses = 1
$sr = GetDword "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" "SecureResponses"
Emit dns_secure_responses 2 ($sr -eq 1) "SecureResponses=$sr"

# 8. DNS Server: EventLogLevel >= 2
$ev = GetDword "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" "EventLogLevel"
Emit dns_event_log_level 2 (($null -ne $ev) -and ($ev -ge 2)) "EventLogLevel=$ev"

# 9. Credential UI no enumerate
$enum = GetDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators"
Emit credui_no_enumerate 2 ($enum -eq 0) "EnumerateAdministrators=$enum"

# 10. Print Spooler disabled
$sp = Get-Service -Name Spooler -ErrorAction SilentlyContinue
$spOk = ($null -eq $sp) -or ($sp.StartType -eq "Disabled")
Emit spooler_disabled 2 $spOk "StartType=$($sp.StartType)"

# 11. WinRM disabled
$wr = Get-Service -Name WinRM -ErrorAction SilentlyContinue
$wrOk = ($null -eq $wr) -or ($wr.StartType -eq "Disabled")
Emit winrm_disabled 2 $wrOk "StartType=$($wr.StartType)"

# 12. auditpol User Account Management has Failure
$audit = (auditpol.exe /get /subcategory:"User Account Management") -join "`n"
Emit audit_uam_failure 1 ($audit -match "Failure") "auditpol UAM output"

# ---- service probes -----------------------------------------------------------
$adminExists = $null -ne (Get-LocalUser -Name $admin -ErrorAction SilentlyContinue)
$adminInGroup = $false
try {
    $adminInGroup = $null -ne (Get-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction SilentlyContinue)
} catch {}
Emit admin_user_preserved 0 ($adminExists -and $adminInGroup) "exists=$adminExists inAdmins=$adminInGroup" service

exit 0
