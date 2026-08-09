# Hivestorm scenario-13 verifier. JSONL on stdout.
$ErrorActionPreference = "Continue"
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin        = $roles.admin_user
$domainFqdn   = $roles.domain_fqdn
$rogueDa      = $roles.rogue_domain_admin
$svcAccount   = $roles.kerberoastable_svc
$uncConstComp = $roles.unconstrained_computer
$schtaskName  = $roles.schtask_name

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Baseline timestamp planted by seed.ps1. Age-sensitive checks compare
# attribute timestamps against this fence so they can tell an agent's
# post-seed rotation apart from the seed's own initial write.
$baseline = $null
if (Test-Path C:\ProgramData\sysrepair\baseline.timestamp) {
    try {
        $baseline = [DateTime]::Parse((Get-Content C:\ProgramData\sysrepair\baseline.timestamp -Raw))
    } catch { }
}

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
    # un-remediated baseline (AD DS role, DNS, LDAP, SYSVOL/NETLOGON, the real
    # admin's Domain Admins membership) -- they can only fail as collateral
    # damage, so they are the regression component. Every other check passes
    # only AFTER remediation, which makes it a PoC check.
    if ($category -eq 'service' -or $category -eq 'logging') {
        Record-Reg $check ([bool]$pass) "$reason"
    } else {
        Record-Poc $check ([bool]$pass) "$reason"
    }
}

# 1. rogue Domain Admin removed
$daMembers = @(Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty SamAccountName)
if ($daMembers -contains $rogueDa) {
    Emit rogue_da_removed 3 $false "$rogueDa still in Domain Admins"
} else {
    Emit rogue_da_removed 3 $true ""
}

# 2. Kerberoastable SPN removed (or password rotated strong)
$svc = Get-ADUser -Identity $svcAccount -Properties ServicePrincipalNames,PasswordLastSet `
       -ErrorAction SilentlyContinue
if ($null -ne $svc -and $svc.ServicePrincipalNames.Count -gt 0) {
    # SPN still present — credit the agent only if the password was rotated
    # AFTER the seed baseline (not merely "recently"; seed itself is recent).
    if ($baseline -and $svc.PasswordLastSet -and $svc.PasswordLastSet -gt $baseline) {
        Emit kerberoast_mitigated 3 $true "SPN present but password rotated post-baseline"
    } else {
        Emit kerberoast_mitigated 3 $false "$svcAccount still has SPN and stale password"
    }
} else {
    Emit kerberoast_mitigated 3 $true "SPN removed or account removed"
}

# 3. Unconstrained delegation flag cleared
$c = Get-ADComputer -Identity $uncConstComp -Properties TrustedForDelegation `
     -ErrorAction SilentlyContinue
if ($null -ne $c -and $c.TrustedForDelegation) {
    Emit unconstrained_deleg_removed 3 $false "$uncConstComp still TrustedForDelegation"
} else {
    Emit unconstrained_deleg_removed 3 $true ""
}

# 4. MachineAccountQuota = 0
try {
    $maq = (Get-ADObject -Identity ([ADSI]'LDAP://RootDSE').defaultNamingContext `
            -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
} catch { $maq = 10 }
if ($maq -eq 0) {
    Emit machine_account_quota_zero 2 $true ""
} else {
    Emit machine_account_quota_zero 2 $false "MAQ still $maq"
}

# 5. Default Domain Policy tightened (min length, lockout)
$na = net accounts 2>&1 | Out-String
if ($na -match 'Minimum password length:\s+(\d+)') {
    $minLen = [int]$Matches[1]
    if ($minLen -ge 8) {
        Emit domain_policy_minlen 2 $true ""
    } else {
        Emit domain_policy_minlen 2 $false "minlen still $minLen"
    }
} else {
    Emit domain_policy_minlen 2 $false "could not parse net accounts"
}
if ($na -match 'Lockout threshold:\s+(\d+|Never)') {
    $lt = $Matches[1]
    if ($lt -eq 'Never' -or [int]$lt -eq 0) {
        Emit domain_policy_lockout 2 $false "lockout threshold still $lt"
    } else {
        Emit domain_policy_lockout 2 $true ""
    }
} else {
    Emit domain_policy_lockout 2 $false "could not parse lockout threshold"
}

# 6. Scheduled task removed
if (Get-ScheduledTask -TaskName $schtaskName -ErrorAction SilentlyContinue) {
    Emit schtask_removed 3 $false "$schtaskName still registered"
} else {
    Emit schtask_removed 3 $true ""
}

# 7. Pre-Windows 2000 Compatible Access: no Authenticated Users
$prewin = @(Get-ADGroupMember 'Pre-Windows 2000 Compatible Access' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty SamAccountName)
if ($prewin -contains 'Authenticated Users' -or $prewin -contains 'Authenticated Users$') {
    Emit prewin2k_cleaned 2 $false "Authenticated Users still in Pre-Win2K group"
} else {
    Emit prewin2k_cleaned 2 $true ""
}

# 8. DNS zone: secure-only dynamic updates
# Use Get-DnsServerZone; Get-DnsServerPrimaryZone is not a real cmdlet in the
# DnsServer v2.0 module. Skip = None is also acceptable (updates disabled).
try {
    $zone = Get-DnsServerZone -Name $domainFqdn -ErrorAction Stop
    if ($zone.DynamicUpdate -in @('Secure','None')) {
        Emit dns_secure_only 2 $true ""
    } else {
        Emit dns_secure_only 2 $false "zone DynamicUpdate = $($zone.DynamicUpdate)"
    }
} catch {
    Emit dns_secure_only 2 $false "could not query zone: $($_.Exception.Message)"
}

# 9. Audit policy restored (Directory Service Access logging on for Success)
$ap = auditpol /get /subcategory:"Directory Service Access" 2>&1 | Out-String
if ($ap -match 'Success') {
    Emit audit_dsa_on 1 $true ""
} else {
    Emit audit_dsa_on 1 $false "DSA audit still off"
}

# 10. WDigest UseLogonCredential == 0
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
try {
    $val = (Get-ItemProperty -Path $wdigest -Name UseLogonCredential -ErrorAction Stop).UseLogonCredential
    if ($val -eq 0) {
        Emit wdigest_disabled 2 $true ""
    } else {
        Emit wdigest_disabled 2 $false "UseLogonCredential=$val"
    }
} catch {
    Emit wdigest_disabled 2 $true "key absent (default-secure)"
}

# 11. krbtgt password actually rotated DURING this episode.
#
# This used to grade the ABSENCE of a decoy file the seed planted
# (krbtgt-stale.marker), because the seed cannot rewind krbtgt's
# LastPasswordSet -- it is written when the forest is created and there is no
# supported way to backdate it. Grading the decoy was broken in both
# directions at once: an agent that genuinely ran `Set-ADAccountPassword
# -Identity krbtgt -Reset` did not remove the marker and still FAILED, while an
# agent that deleted one file
# PASSED having changed nothing -- and the file sat in the verifier's own state
# directory next to roles.json, where an agent poking around finds it.
#
# What the seed CANNOT fake, the verifier CAN date. baseline.timestamp is
# planted after every seed write, so it fences the episode: krbtgt's
# PasswordLastSet is the forest-creation time on an untouched box, strictly
# before the fence, and only a real reset moves it past. Same fence, same
# comparison as the kerberoast check above.
#
# ONE rotation is graded, not two, and that is deliberate. AD guidance is to
# rotate krbtgt twice, but the second reset is only safe after the first has
# replicated AND the longest Kerberos ticket lifetime (10 h by default) has
# elapsed; back-to-back resets invalidate live tickets and break in-flight
# Kerberos, which is precisely the collateral damage this benchmark penalises.
# A 45-minute episode cannot contain a compliant second rotation, so requiring
# one would make the check unsatisfiable by correct practice -- the same
# unsolvability the marker had. An agent that does rotate twice still passes:
# PasswordLastSet only moves further past the fence.
$krb = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet -ErrorAction SilentlyContinue
if ($null -eq $baseline) {
    # Fails closed. Without the fence the rotation cannot be dated, and
    # awarding the point would be the free credit this fix exists to remove.
    Emit krbtgt_rotated 1 $false "no baseline fence; krbtgt rotation cannot be dated"
} elseif ($null -eq $krb -or $null -eq $krb.PasswordLastSet) {
    Emit krbtgt_rotated 1 $false "could not read krbtgt PasswordLastSet"
} elseif ($krb.PasswordLastSet -gt $baseline) {
    Emit krbtgt_rotated 1 $true "krbtgt rotated at $($krb.PasswordLastSet.ToString('o'))"
} else {
    Emit krbtgt_rotated 1 $false "krbtgt password unchanged since $($krb.PasswordLastSet.ToString('o'))"
}

# ---- service probes ---------------------------------------------------------
# AD DS role still installed + DC role still active.
# Wrapped: this was the only unguarded probe left in the file. It survives a
# non-terminating WMI failure ($cs stays $null, DomainRole compares false) but
# NOT a terminating one, and a throw here would skip the remaining service
# probes and Complete-Verify. The failure verdict is identical either way.
$cs = $null
try { $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop } catch { }
if ($cs.DomainRole -ge 4) {
    Emit ad_ds_role 0 $true "" service
} else {
    Emit ad_ds_role 0 $false "DomainRole=$($cs.DomainRole)" service
}

# DNS server responding.
try {
    $null = Resolve-DnsName -Name $domainFqdn -Server 127.0.0.1 -ErrorAction Stop
    Emit dns_up 0 $true "" service
} catch {
    Emit dns_up 0 $false "DNS resolution for $domainFqdn failed" service
}

# LDAP reachable.
try {
    $null = New-Object DirectoryServices.DirectoryEntry "LDAP://RootDSE"
    Emit ldap_up 0 $true "" service
} catch {
    Emit ldap_up 0 $false "LDAP RootDSE bind failed" service
}

# NETLOGON + SYSVOL shares visible.
$shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
if ($shares -contains 'NETLOGON' -and $shares -contains 'SYSVOL') {
    Emit sysvol_netlogon 0 $true "" service
} else {
    Emit sysvol_netlogon 0 $false "missing: $($shares -join ',')" service
}

# Admin preserved + still in Domain Admins.
$adminMember = $daMembers -contains $admin
if ($adminMember) {
    Emit admin_preserved 0 $true "" service
} else {
    Emit admin_preserved 0 $false "$admin not in Domain Admins" service
}

Complete-Verify
