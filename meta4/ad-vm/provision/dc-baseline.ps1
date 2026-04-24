# meta4/ad-vm/provision/dc-baseline.ps1
# Promotes to corp.local forest root, seeds directory with 8 users, 3 OUs.
# Idempotent: safe to re-run; exits 0 if already provisioned.
#
# Architecture note:
#   Install-ADDSForest destroys the local SAM the moment it completes
#   (regardless of -NoRebootOnCompletion). If called inside this WinRM-driven
#   provisioner, the local 'vagrant' account disappears and vagrant-reload's
#   subsequent graceful-shutdown handshake 401s. To avoid that, pass 1 here
#   only installs the AD DS role + stages a self-driving bootstrap chain
#   (Meta4-Bootstrap scheduled task). Pass 2, which runs after :reload, waits
#   for the bootstrap chain to write C:\meta4-setup\BOOTSTRAP_COMPLETE before
#   declaring success -- otherwise vagrant up would exit 0 while DCPROMO is
#   still mid-chain and the lab would be half-provisioned.
#
#   Bootstrap phases (all inside bootstrap.ps1, driven by the startup task):
#     A. pre-DCPROMO boot: Install-ADDSForest -NoReboot -> schedule reboot
#     B. post-DCPROMO boot: wait AD Web Services, seed OUs + users +
#        Domain Admins, write BOOTSTRAP_COMPLETE marker, unregister self.

$ErrorActionPreference = 'Stop'

$domainName      = 'corp.local'
$netbiosName     = 'CORP'
$adminPassword   = 'Password1!'
$setupDir        = 'C:\meta4-setup'
$completeMarker  = Join-Path $setupDir 'BOOTSTRAP_COMPLETE'

# --- 0. idempotency guard ---
$alreadyPromoted = $false
try {
    if ((Get-ADDomain -ErrorAction Stop).DNSRoot -eq $domainName) {
        $alreadyPromoted = $true
    }
} catch { }

if ($alreadyPromoted) {
    Write-Host "[dc-baseline] already forest root of $domainName, running health check"
    if (-not (Test-Path $completeMarker)) {
        New-Item -ItemType File -Path $completeMarker -Force | Out-Null
    }
    Write-Host "[dc-baseline] repadmin /showrepl"
    repadmin /showrepl | Out-Null
    Write-Host "[dc-baseline] dcdiag /test:replications"
    dcdiag /test:replications /q
    Write-Host "[dc-baseline] COMPLETE"
    exit 0
}

# Pass 2 entry: DC-role is installed (because pass 1 ran) but domain isn't
# live yet. That means we're the post-:reload invocation running during the
# bootstrap chain. Wait for the chain's sentinel marker rather than re-running
# pass 1 logic -- which would register a duplicate scheduled task and let
# vagrant up exit 0 while DCPROMO is still happening.
$dcRoleInstalled = (Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue).Installed
if ($dcRoleInstalled) {
    Write-Host "[dc-baseline] AD DS role installed; waiting for Meta4-Bootstrap chain to finish"
    $deadline = (Get-Date).AddMinutes(30)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $completeMarker) {
            Write-Host "[dc-baseline] BOOTSTRAP_COMPLETE marker found"
            break
        }
        Start-Sleep -Seconds 15
    }
    if (-not (Test-Path $completeMarker)) {
        Write-Host "[dc-baseline] timed out after 30 min waiting for bootstrap chain"
        if (Test-Path 'C:\meta4-setup\bootstrap.log') {
            Write-Host "--- bootstrap.log tail ---"
            Get-Content 'C:\meta4-setup\bootstrap.log' -Tail 40
        }
        throw "[dc-baseline] Meta4-Bootstrap chain did not complete within 30 min"
    }
    # Marker present -> DC should be promoted. Fall through to health check.
    Write-Host "[dc-baseline] re-checking Get-ADDomain after bootstrap completion"
    Import-Module ActiveDirectory
    $d = Get-ADDomain -ErrorAction Stop
    if ($d.DNSRoot -ne $domainName) {
        throw "[dc-baseline] marker present but domain mismatch: $($d.DNSRoot) != $domainName"
    }
    Write-Host "[dc-baseline] repadmin /showrepl"
    repadmin /showrepl | Out-Null
    Write-Host "[dc-baseline] dcdiag /test:replications"
    dcdiag /test:replications /q
    Write-Host "[dc-baseline] COMPLETE"
    exit 0
}

# --- pass 1: install role + register self-driving bootstrap chain ---
Write-Host "[dc-baseline] installing AD DS role"
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

New-Item -ItemType Directory -Path $setupDir -Force | Out-Null
$bootstrapScript = Join-Path $setupDir 'bootstrap.ps1'

# Self-driving, reboot-safe bootstrap. Phase A = DCPROMO. Phase B = seed +
# marker write + self-unregister. The promoted-probe waits up to 5 min for
# AD Web Services on post-DCPROMO boot, so a slow NTDS startup no longer
# triggers a spurious second Install-ADDSForest (which would error with
# "DomainLevel argument not recognized" since the DC role is already live).
$bootstrapBody = @'
$ErrorActionPreference = "Stop"
$log       = "C:\meta4-setup\bootstrap.log"
$marker    = "C:\meta4-setup\BOOTSTRAP_COMPLETE"
function Log($m) { "[$(Get-Date -Format s)] $m" | Add-Content $log }
Log "Meta4-Bootstrap fired"

# Robust promoted probe: if the DC role's NTDS service exists, this machine
# was DCPROMO'd even if AD Web Services haven't come up yet. Wait up to 5 min
# for AD to be query-ready before giving up and re-running Install-ADDSForest.
$ntdsPresent = [bool](Get-Service -Name NTDS -ErrorAction SilentlyContinue)
$promoted    = $false
if ($ntdsPresent) {
    Log "NTDS service present; waiting for AD Web Services"
    $tries = 0
    while ($tries -lt 30) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            if ((Get-ADDomain -ErrorAction Stop).DNSRoot -eq "corp.local") {
                $promoted = $true
                break
            }
        } catch { }
        Start-Sleep -Seconds 10
        $tries++
    }
    Log "promoted=$promoted after $($tries * 10)s wait"
}

if (-not $promoted) {
    Log "not yet promoted; running Install-ADDSForest"
    try {
        Install-ADDSForest `
          -DomainName corp.local `
          -DomainNetbiosName CORP `
          -SafeModeAdministratorPassword (ConvertTo-SecureString "Vagrant1DSRM!" -AsPlainText -Force) `
          -ForestMode WinThreshold `
          -DomainMode WinThreshold `
          -InstallDns:$true `
          -NoRebootOnCompletion:$true `
          -Force:$true | Out-Null
        Log "Install-ADDSForest returned; rebooting in 5s"
    } catch {
        Log "Install-ADDSForest ERROR: $_"
        throw
    }
    shutdown.exe /r /t 5 /f /c "Meta4-Bootstrap: completing DCPROMO"
    exit 0
}

Log "Phase B: seeding directory"
try {
    if (-not (Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.SamAccountName -eq "vagrant" })) {
        # DCPROMO migrated local 'vagrant' into the domain (SamAccount intact,
        # no group memberships). Promote it to Domain Admins so the post-DCPROMO
        # WinRM reconnect as CORP\vagrant has admin rights.
        Add-ADGroupMember -Identity "Domain Admins" -Members vagrant
        Log "added CORP\vagrant to Domain Admins"
    }

    foreach ($ou in @("Corp","IT","Service")) {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $ou -Path "DC=corp,DC=local" -ProtectedFromAccidentalDeletion:$false
            Log "created OU=$ou"
        }
    }

    $seedUsers = @(
        @{ name="alice";   ou="Corp"    },
        @{ name="bob";     ou="Corp"    },
        @{ name="carol";   ou="Corp"    },
        @{ name="dave";    ou="IT"      },
        @{ name="eve";     ou="IT"      },
        @{ name="svc_sql"; ou="Service" },
        @{ name="svc_web"; ou="Service" },
        @{ name="svc_bkp"; ou="Service" }
    )
    foreach ($u in $seedUsers) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.name)'" -ErrorAction SilentlyContinue)) {
            New-ADUser -Name $u.name -SamAccountName $u.name `
              -AccountPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force) `
              -Path "OU=$($u.ou),DC=corp,DC=local" `
              -Enabled $true -PasswordNeverExpires $true
            Log "created user=$($u.name) ou=$($u.ou)"
        }
    }

    # Admin Administrator pwd -> Password1! so ca-baseline.ps1 can domain-join
    # using CORP\Administrator without the unknown-post-DCPROMO pwd problem.
    Set-ADAccountPassword -Identity Administrator -Reset `
      -NewPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force)
    Set-ADUser -Identity Administrator -PasswordNeverExpires $true
    Log "reset CORP\Administrator password"

    New-Item -ItemType File -Path $marker -Force | Out-Null
    Log "wrote BOOTSTRAP_COMPLETE marker"

    schtasks /Delete /TN "Meta4-Bootstrap"        /F | Out-Null
    schtasks /Delete /TN "Meta4-Bootstrap-Rescue" /F 2>$null | Out-Null
    Log "Meta4-Bootstrap unregistered, done"
} catch {
    Log "ERROR in Phase B: $_"
    throw
}
'@
Set-Content -Path $bootstrapScript -Value $bootstrapBody -Encoding UTF8

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
               -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$bootstrapScript`""
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
               -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
               -StartWhenAvailable -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'Meta4-Bootstrap' `
  -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "[dc-baseline] registered Meta4-Bootstrap startup task"

Write-Host "[dc-baseline] pass 1 complete; awaiting reload + bootstrap.ps1 chain"
exit 0
