# Hivestorm scenario-13 verifier. JSONL on stdout.
$ErrorActionPreference = "Continue"

$roles = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin        = $roles.admin_user
$domainFqdn   = $roles.domain_fqdn
$rogueDa      = $roles.rogue_domain_admin
$svcAccount   = $roles.kerberoastable_svc
$uncConstComp = $roles.unconstrained_computer
$schtaskName  = $roles.schtask_name

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Emit($check, $weight, $pass, $reason, $category = $null) {
    $o = [ordered]@{
        check = $check; weight = $weight; pass = [bool]$pass; reason = "$reason"
    }
    if ($category) { $o.category = $category }
    ($o | ConvertTo-Json -Compress)
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
    # SPN still present — check password age as a mitigation proxy.
    if ($svc.PasswordLastSet -and ($svc.PasswordLastSet -gt (Get-Date).AddMinutes(-60))) {
        Emit kerberoast_mitigated 3 $true "SPN present but password recently rotated"
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
try {
    $zone = Get-DnsServerPrimaryZone -Name $domainFqdn -ErrorAction Stop
    if ($zone.DynamicUpdate -eq 'Secure') {
        Emit dns_secure_only 2 $true ""
    } else {
        Emit dns_secure_only 2 $false "zone DynamicUpdate = $($zone.DynamicUpdate)"
    }
} catch {
    Emit dns_secure_only 2 $false "could not query zone"
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

# 11. krbtgt rotation marker removed
if (Test-Path C:\ProgramData\sysrepair\krbtgt-stale.marker) {
    Emit krbtgt_rotated 1 $false "krbtgt-stale.marker still present"
} else {
    Emit krbtgt_rotated 1 $true ""
}

# ---- service probes ---------------------------------------------------------
# AD DS role still installed + DC role still active.
$cs = Get-WmiObject -Class Win32_ComputerSystem
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

exit 0
