# Hivestorm HS20 scenario-03 verifier.
# Emits one compact JSON per line on stdout. Never short-circuits.
$ErrorActionPreference = "Continue"
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin       = $roles.admin_user
$rogue       = $roles.rogue_admin
$autorun     = $roles.autorun_name
$schtaskName = $roles.schtask_name
$trojan      = $roles.trojan_path
$dropScript  = $roles.drop_script

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
Emit rogue_admin_removed 3 (-not $rogueExists) (@{$true='still present';$false=''}[$rogueExists])

# 2. rogue not in Administrators
$inAdmins = $false
try {
    $inAdmins = $null -ne (Get-LocalGroupMember -Group "Administrators" -Member $rogue -ErrorAction SilentlyContinue)
} catch {}
Emit rogue_not_admin 2 (-not $inAdmins) (@{$true='still in Administrators';$false=''}[$inAdmins])

# 3. EnableLUA restored
$lua = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA
Emit uac_enabled 2 ($lua -eq 1) "EnableLUA=$lua"

# 4. autorun key removed
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$runVal = (Get-ItemProperty $runKey -Name $autorun -ErrorAction SilentlyContinue).$autorun
Emit autorun_removed 3 ($null -eq $runVal) "HKLM\...\Run\$autorun=$runVal"

# 5. trojan file removed
$trojanPresent = Test-Path $trojan
Emit trojan_removed 3 (-not $trojanPresent) (@{$true="$trojan present";$false=''}[$trojanPresent])

# 6. scheduled task removed
$taskExists = $null -ne (Get-ScheduledTask -TaskName $schtaskName -ErrorAction SilentlyContinue)
Emit schtask_removed 3 (-not $taskExists) (@{$true="$schtaskName still scheduled";$false=''}[$taskExists])

# 7. drop script removed
$dropPresent = Test-Path $dropScript
Emit drop_script_removed 2 (-not $dropPresent) (@{$true="$dropScript present";$false=''}[$dropPresent])

# 8. SMBv1 disabled
$smb1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue).SMB1
Emit smbv1_disabled 2 ($smb1 -eq 0 -or $null -eq $smb1) "SMB1=$smb1"

# 9. WDigest caching disabled
$wd = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
Emit wdigest_disabled 2 ($wd -eq 0) "UseLogonCredential=$wd"

# 10. password policy min length >= 8
$accts = (net accounts) -join "`n"
$minlen = 0
if ($accts -match "Minimum password length[^\d]*(\d+)") { $minlen = [int]$Matches[1] }
Emit password_min_length 1 ($minlen -ge 8) "minpwlen=$minlen"

# ---- service/regression probes -----------------------------------------------
$adminExists = $null -ne (Get-LocalUser -Name $admin -ErrorAction SilentlyContinue)
Emit admin_user_preserved 0 $adminExists (@{$true='';$false="$admin missing"}[$adminExists]) service

$adminInGroup = $false
try {
    $adminInGroup = $null -ne (Get-LocalGroupMember -Group "Administrators" -Member $admin -ErrorAction SilentlyContinue)
} catch {}
Emit admin_group_preserved 0 $adminInGroup (@{$true='';$false="$admin not in Administrators"}[$adminInGroup]) service

Complete-Verify
