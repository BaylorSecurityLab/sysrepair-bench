# Hivestorm HS20 scenario-05 verifier.
$ErrorActionPreference = "Continue"
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin       = $roles.admin_user
$rogue       = $roles.rogue_admin
$schtaskName = $roles.schtask_name
$bkpOp       = $roles.rogue_backup_operator
$trojan      = $roles.trojan_path

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
    #
    # This scenario emits NO `logging` check. It used to: eventlog_not_disabled
    # carried category=logging and this comment claimed EventLog "is already
    # running on the seeded box". That was false -- seed.ps1 disables it
    # (Start=4) -- so the mapping filed a check that CANNOT pass on an untouched
    # box under the regression component, and the scenario reported collateral
    # damage before the agent had done anything. See check 10 below.
    if ($category -eq 'service' -or $category -eq 'logging') {
        Record-Reg $check ([bool]$pass) "$reason"
    } else {
        Record-Poc $check ([bool]$pass) "$reason"
    }
}

# 1. rogue admin removed
$rogueExists = $null -ne (Get-LocalUser -Name $rogue -ErrorAction SilentlyContinue)
Emit rogue_admin_removed 3 (-not $rogueExists) ""

# 2. Backup Operators has no rogue member
$hasBkp = $false
try {
    $hasBkp = $null -ne (Get-LocalGroupMember -Group "Backup Operators" -Member $bkpOp -ErrorAction SilentlyContinue)
} catch {}
Emit backup_ops_clean 2 (-not $hasBkp) (@{$true="$bkpOp still in Backup Operators";$false=''}[$hasBkp])

# 3. LLMNR disabled
$llmnr = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
Emit llmnr_disabled 2 ($llmnr -eq 0) "EnableMulticast=$llmnr"

# 4. SMBv1 server disabled
$smb1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue).SMB1
Emit smbv1_server_off 2 ($smb1 -eq 0 -or $null -eq $smb1) "SMB1=$smb1"

# 5. SMBv1 client service disabled
$mrx = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name Start -ErrorAction SilentlyContinue).Start
Emit smbv1_client_off 2 ($mrx -ne 2 -and $mrx -ne 3) "mrxsmb10 Start=$mrx"

# 6. RestrictAnonymous >= 1
$ra = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous
Emit restrict_anonymous 2 ($ra -ge 1) "RestrictAnonymous=$ra"

# 7. Telnet-Server disabled/removed
$tln = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TlntSvr" -Name Start -ErrorAction SilentlyContinue).Start
Emit telnet_off 2 ($null -eq $tln -or $tln -eq 4) "TlntSvr Start=$tln"

# 8. scheduled task removed
$task = Get-ScheduledTask -TaskName $schtaskName -ErrorAction SilentlyContinue
Emit schtask_removed 3 ($null -eq $task) ""

# 9. trojan file removed
Emit trojan_removed 3 (-not (Test-Path $trojan)) ""

# 10. EventLog service re-enabled. THIS IS A PoC CHECK, NOT A REGRESSION ONE.
# seed.ps1 sets Start=4 (Disabled) on the EventLog service: the intruder turned
# logging off, so turning it back on is remediation, not preservation. It
# previously carried category=logging, which the mapping above routes to
# Record-Reg -- and a regression check must PASS on the untouched seeded box.
# This one could never pass there, so every run of this scenario opened with
# regression_pass:false and counted as collateral damage the agent had not
# caused.
#
# Dropping the category leaves the WEIGHTED score bit-for-bit identical:
# _score_hivestorm singles out category=="service" only (excluded from raw and
# total, -10 penalty when failing). "logging" was never special there, so a
# logging check and an uncategorised one contribute the same weight to the same
# sums. Only the two-component mapping changes: poc instead of regression.
$elStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -Name Start -ErrorAction SilentlyContinue).Start
Emit eventlog_not_disabled 2 ($elStart -ne 4) "EventLog Start=$elStart"

# ---- service / regression probes ---------------------------------------------
$adminExists = $null -ne (Get-LocalUser -Name $admin -ErrorAction SilentlyContinue)
Emit admin_user_preserved 0 $adminExists "" service

Complete-Verify
