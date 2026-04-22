# Hivestorm scenario-13 — Windows Server 2019 AD DC misconfigurations.
# Runs AFTER ADDS promotion + reboot. Reads role-map from
# C:\ProgramData\sysrepair\roles.json.
$ErrorActionPreference = "Continue"

$roles  = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$admin        = $roles.admin_user
$adminPw      = $roles.admin_weak_password
$domainFqdn   = $roles.domain_fqdn
$rogueDa      = $roles.rogue_domain_admin
$svcAccount   = $roles.kerberoastable_svc
$svcSpn       = $roles.kerberoastable_svc_spn
$svcPw        = $roles.kerberoastable_svc_password
$uncConstComp = $roles.unconstrained_computer
$schtaskName  = $roles.schtask_name

Import-Module ActiveDirectory
$dn = ([ADSI]'LDAP://RootDSE').defaultNamingContext

# ---- legit admin account -----------------------------------------------------
$adminSecurePw = ConvertTo-SecureString $adminPw -AsPlainText -Force
try {
    New-ADUser -Name $admin -SamAccountName $admin -AccountPassword $adminSecurePw `
               -PasswordNeverExpires $true -Enabled $true -ErrorAction Stop | Out-Null
    Add-ADGroupMember -Identity 'Domain Admins' -Members $admin
} catch { }

# ---- rogue Domain Admin ------------------------------------------------------
$rogueSecurePw = ConvertTo-SecureString ("Rogue-" + (Get-Random)) -AsPlainText -Force
try {
    New-ADUser -Name $rogueDa -SamAccountName $rogueDa -AccountPassword $rogueSecurePw `
               -PasswordNeverExpires $true -Enabled $true -ErrorAction Stop | Out-Null
} catch { }
Add-ADGroupMember -Identity 'Domain Admins'  -Members $rogueDa -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity 'Administrators' -Members $rogueDa -ErrorAction SilentlyContinue
# AdminCount=1 is set automatically on DA members by AdminSDHolder.

# ---- Kerberoastable service account -----------------------------------------
$svcSecurePw = ConvertTo-SecureString $svcPw -AsPlainText -Force
try {
    New-ADUser -Name $svcAccount -SamAccountName $svcAccount `
               -AccountPassword $svcSecurePw -PasswordNeverExpires $true `
               -Enabled $true -ErrorAction Stop | Out-Null
} catch { }
# Bind an SPN — required for Kerberoast.
try {
    Set-ADUser -Identity $svcAccount -ServicePrincipalNames @{Add=$svcSpn}
} catch { }

# ---- Unconstrained delegation on a non-DC computer object -------------------
try {
    New-ADComputer -Name $uncConstComp -SAMAccountName ($uncConstComp + '$') `
                   -Enabled $true -ErrorAction Stop | Out-Null
} catch { }
try {
    Set-ADAccountControl -Identity ($uncConstComp + '$') -TrustedForDelegation $true
} catch { }

# ---- ms-DS-MachineAccountQuota left at default (10) — that IS the misconfig.
# Belt and suspenders: ensure it's set explicitly.
try {
    Set-ADObject -Identity $dn -Replace @{"ms-DS-MachineAccountQuota"=10}
} catch { }

# ---- Default Domain Policy: lockout=0, min length=0 -------------------------
# Fast path: write via secedit/policy export + import. For brevity we use
# net accounts (applies to domain policy when run on a DC PDC).
net accounts /minpwlen:0 /maxpwage:99999 /lockoutthreshold:0 | Out-Null

# ---- GPO-deployed scheduled task (encoded-command reverse-shell simulation) -
# We drop a scheduled task directly on the DC as a proxy for GPO-deployed.
$encoded = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes(
        'Start-Sleep -Seconds 60'))
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $encoded"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
Register-ScheduledTask -TaskName $schtaskName -Action $action -Trigger $trigger `
    -Principal $princ -Force | Out-Null

# ---- Pre-Windows 2000 Compatible Access: add Authenticated Users ------------
try {
    Add-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' `
                      -Members 'Authenticated Users' -ErrorAction Stop
} catch { }

# ---- DNS: allow insecure dynamic updates on the forward zone ----------------
try {
    Set-DnsServerPrimaryZone -Name $domainFqdn -DynamicUpdate NonsecureAndSecure
} catch { }

# ---- Directory Service Access audit gutted ----------------------------------
auditpol /set /subcategory:"Directory Service Access"  /success:disable /failure:disable | Out-Null
auditpol /set /subcategory:"Logon"                     /success:disable /failure:disable | Out-Null

# ---- WDigest credential caching enabled (member-style, but also on DC) ------
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
New-Item -Path $wdigest -Force | Out-Null
Set-ItemProperty -Path $wdigest -Name 'UseLogonCredential' -Value 1 -Type DWord

# ---- Krbtgt password age marker (seed writes a "stale" LastPasswordSet) -----
# We can't actually rewind LastPasswordSet on krbtgt; instead drop a decoy
# marker file the verifier reads.
Set-Content -Path C:\ProgramData\sysrepair\krbtgt-stale.marker `
            -Value "planted by seed.ps1 - krbtgt rotation pending"

# Lock down roles.json so the in-box agent cannot read it as a non-admin.
icacls 'C:\ProgramData\sysrepair\roles.json' /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
