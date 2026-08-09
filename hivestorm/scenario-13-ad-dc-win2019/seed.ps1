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
# Applies to domain policy when run on the PDC emulator.
#
# /maxpwage TAKES 1-999 OR "UNLIMITED". It was 99999, which net accounts
# rejects with "You entered an invalid value for the /MAXPWAGE option" -- and it
# rejects the ENTIRE invocation, so /minpwlen and /lockoutthreshold were never
# applied either. The domain kept its defaults (MinPasswordLength 7,
# MaxPasswordAge 42 days) while the seed reported success, because seed.ps1
# runs with $ErrorActionPreference = "Continue" and a native command's failure
# does not raise.
#
# Found by running the seed on the AutomatedLab DC and reading the domain
# policy back; the Vagrant path had the same bug and nothing ever looked at it.
net accounts /minpwlen:0 /maxpwage:unlimited /lockoutthreshold:0 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "[seed-13] net accounts failed ($LASTEXITCODE); the domain password policy was NOT weakened"
}

# Verify rather than assume: a seed that silently no-ops leaves checks passing
# that the scenario intends to fail, which reads as an agent success it did not
# earn.
try {
    $pol = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    if ($pol.MinPasswordLength -ne 0) {
        Write-Error "[seed-13] MinPasswordLength is $($pol.MinPasswordLength), expected 0"
    }
} catch {
    Write-Error "[seed-13] could not read back the domain password policy: $_"
}

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

# ---- Krbtgt: NOTHING IS PLANTED, AND THAT IS THE POINT ----------------------
# krbtgt's LastPasswordSet is written when the forest is created and cannot be
# rewound, so this used to drop a decoy marker file for verify.ps1 to grade.
# That made the check measure the marker instead of the account: rotating
# krbtgt for real did not remove the file (so the correct action still failed)
# and deleting the file rotated nothing (so a no-op still passed).
#
# The stale password is therefore left as the seed finds it -- genuinely stale,
# because the forest was built long before this run -- and verify.ps1 grades the
# rotation against the baseline.timestamp fence written immediately below.
# Nothing needs to be seeded for that to work.
#
# Removed rather than ignored: a re-seed over an already-seeded DC would
# otherwise leave the old decoy sitting in the verifier's state directory,
# where it is a misleading artefact for both the agent and the next reader.
Remove-Item -Path C:\ProgramData\sysrepair\krbtgt-stale.marker `
            -Force -ErrorAction SilentlyContinue

# ---- baseline timestamp --------------------------------------------------
# Fence planted AFTER every seed write so verify.ps1 can distinguish
# an agent's post-seed rotation from the seed's own initial attribute set.
(Get-Date).ToUniversalTime().ToString("o") | Set-Content -Path C:\ProgramData\sysrepair\baseline.timestamp

# Lock down roles.json so the in-box agent cannot read it as a non-admin.
icacls 'C:\ProgramData\sysrepair\roles.json' /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
