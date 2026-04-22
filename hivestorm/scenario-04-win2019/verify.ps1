# Hivestorm HS20 scenario-04 verifier.
$ErrorActionPreference = "Continue"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin       = $roles.admin_user
$rogue       = $roles.rogue_admin
$schtaskName = $roles.schtask_name
$fwRule      = $roles.rogue_firewall_rule

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

# 2. rogue not in Administrators
$inAdmins = $false
try {
    $inAdmins = $null -ne (Get-LocalGroupMember -Group "Administrators" -Member $rogue -ErrorAction SilentlyContinue)
} catch {}
Emit rogue_not_admin 2 (-not $inAdmins) ""

# 3. SMB signing required
$lm = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
Emit smb_signing_required 2 ($lm.RequireSecuritySignature -eq 1) "RequireSecuritySignature=$($lm.RequireSecuritySignature)"

# 4. LmCompatibilityLevel >= 5
$lc = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
Emit lmcompat_hardened 2 ($lc -ge 5) "LmCompatibilityLevel=$lc"

# 5. WDigest disabled
$wd = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
Emit wdigest_disabled 2 ($wd -eq 0) "UseLogonCredential=$wd"

# 6. rogue firewall rule removed — check both the live NetFirewallRule cmdlet
# (works on real hosts / VMs where MpsSvc runs) and the registry-persisted
# copy under FirewallPolicy\FirewallRules (works on Server-Core containers
# where the live firewall API is unreachable). Removal via either channel
# counts; presence on either channel fails the check.
$fwRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
$regPresent = $false
try {
    $reg = Get-ItemProperty -Path $fwRegPath -Name $fwRule -ErrorAction SilentlyContinue
    if ($reg) { $regPresent = $null -ne $reg.$fwRule }
} catch {}
$live = Get-NetFirewallRule -DisplayName $fwRule -ErrorAction SilentlyContinue
$present = $regPresent -or ($null -ne $live)
Emit firewall_rule_removed 3 (-not $present) "reg=$regPresent live=$($null -ne $live)"

# 7. scheduled task removed
$task = Get-ScheduledTask -TaskName $schtaskName -ErrorAction SilentlyContinue
Emit schtask_removed 3 ($null -eq $task) ""

# 8. audit logon success enabled
$audit = (auditpol.exe /get /subcategory:"Logon") -join "`n"
Emit audit_logon_success 1 ($audit -match "Success") "auditpol output"

# 9. PowerShell v2 engine disabled (registry key removed or disabled)
$ps2 = Get-Item "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -ErrorAction SilentlyContinue
$ps2ver = $null
if ($ps2) { $ps2ver = (Get-ItemProperty $ps2.PSPath -Name PowerShellVersion -ErrorAction SilentlyContinue).PowerShellVersion }
Emit psv2_disabled 1 ($null -eq $ps2 -or $ps2ver -ne "2.0") "PowerShellVersion=$ps2ver"

# ---- service probes -----------------------------------------------------------
$adminExists = $null -ne (Get-LocalUser -Name $admin -ErrorAction SilentlyContinue)
Emit admin_user_preserved 0 $adminExists "" service
$adminInGroup = $false
try {
    $adminInGroup = $null -ne (Get-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction SilentlyContinue)
} catch {}
Emit admin_group_preserved 0 $adminInGroup "" service

exit 0
