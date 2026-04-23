# meta4/ad-vm/provision/dc-baseline.ps1
# Promotes to corp.local forest root, seeds directory with 8 users, 3 OUs.
# Idempotent: safe to re-run; exits 0 if already provisioned.
#
# Architecture note:
#   Install-ADDSForest destroys the local SAM the moment it completes
#   (regardless of -NoRebootOnCompletion). If called inside this WinRM-driven
#   provisioner, the local 'vagrant' account disappears and vagrant-reload's
#   subsequent graceful-shutdown handshake 401s. To avoid that, pass 1 here
#   only installs the AD DS role + stages a one-shot startup task chain
#   (bootstrap.ps1) that performs the actual promotion AFTER vagrant-reload
#   has already rebooted. WinRM is set to Manual so no listener comes up
#   until bootstrap.ps1 has created CORP\vagrant and restarted the service.

$ErrorActionPreference = 'Stop'

$domainName      = 'corp.local'
$netbiosName     = 'CORP'
$adminPassword   = 'Password1!'

# --- 0. idempotency guard ---
$alreadyPromoted = $false
try {
    if ((Get-ADDomain -ErrorAction Stop).DNSRoot -eq $domainName) {
        $alreadyPromoted = $true
    }
} catch { }

if ($alreadyPromoted) {
    Write-Host "[dc-baseline] already forest root of $domainName, proceeding to seed pass"
} else {
    Write-Host "[dc-baseline] installing AD DS role"
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

    $setupDir = 'C:\meta4-setup'
    New-Item -ItemType Directory -Path $setupDir -Force | Out-Null
    $bootstrapScript = Join-Path $setupDir 'bootstrap.ps1'

    # Self-driving, reboot-safe bootstrap: runs on every startup via
    # Meta4-Bootstrap startup task until it unregisters itself in the final
    # phase. Handles both the pre-DCPROMO boot (phase A: promote + reboot)
    # and the post-DCPROMO boot (phase B: create CORP\vagrant + start WinRM).
    $bootstrapBody = @'
$ErrorActionPreference = "Stop"
$log = "C:\meta4-setup\bootstrap.log"
function Log($m) { "[$(Get-Date -Format s)] $m" | Add-Content $log }
Log "Meta4-Bootstrap fired"

$promoted = $false
try {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    if ((Get-ADDomain -ErrorAction Stop).DNSRoot -eq "corp.local") {
        $promoted = $true
    }
} catch { }

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

Log "already promoted; waiting for AD Web Services"
$tries = 0
while ($tries -lt 60) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Get-ADDomain -ErrorAction Stop | Out-Null
        break
    } catch {
        Start-Sleep -Seconds 10
        $tries++
    }
}
Log "AD ready after $($tries * 10)s"

try {
    if (-not (Get-ADUser -Filter { SamAccountName -eq "vagrant" } -ErrorAction SilentlyContinue)) {
        New-ADUser -Name vagrant `
          -SamAccountName vagrant `
          -AccountPassword (ConvertTo-SecureString "vagrant" -AsPlainText -Force) `
          -Enabled $true `
          -PasswordNeverExpires $true
        Add-ADGroupMember -Identity "Domain Admins" -Members vagrant
        Log "created CORP\vagrant in Domain Admins"
    } else {
        Log "CORP\vagrant already exists"
    }
    Set-Service WinRM -StartupType Automatic
    Start-Service WinRM
    Log "WinRM re-enabled and started"
    schtasks /Delete /TN "Meta4-Bootstrap" /F | Out-Null
    schtasks /Delete /TN "Meta4-Bootstrap-Rescue" /F 2>$null | Out-Null
    Log "Meta4-Bootstrap unregistered, done"
} catch {
    Log "ERROR in seed phase: $_"
    try { Set-Service WinRM -StartupType Automatic; Start-Service WinRM } catch {}
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

    # Safety net: force WinRM back on after 25 min regardless of primary task
    # outcome, so a failed bootstrap doesn't strand the VM.
    $rescueCmd = Join-Path $setupDir 'winrm-rescue.cmd'
    Set-Content -Path $rescueCmd -Encoding ASCII -Value @'
@echo off
powershell.exe -NoProfile -Command "Set-Service WinRM -StartupType Automatic; Start-Service WinRM"
'@
    $rescueAction    = New-ScheduledTaskAction -Execute $rescueCmd
    $rescueTrigger   = New-ScheduledTaskTrigger -AtStartup
    $rescueTrigger.Delay = 'PT25M'
    Register-ScheduledTask -TaskName 'Meta4-Bootstrap-Rescue' `
      -Action $rescueAction -Trigger $rescueTrigger -Principal $principal `
      -Settings $settings -Force | Out-Null
    Write-Host "[dc-baseline] registered Meta4-Bootstrap-Rescue safety task"

    # Disable WinRM auto-start so the listener stays down across the next
    # two reboots (pre-DCPROMO -> DCPROMO-reboot -> post-DCPROMO). It only
    # comes back up when bootstrap.ps1 has created CORP\vagrant so the
    # vagrant/CORP\vagrant principal matches for vagrant-reload reconnect.
    Set-Service WinRM -StartupType Manual
    Write-Host "[dc-baseline] WinRM set to Manual start; pass 1 complete, awaiting reload"
    exit 0
}

# --- 1. seed OUs, users, groups (runs on second pass, after DC reboot) ---
Import-Module ActiveDirectory

foreach ($ou in @('Corp','IT','Service')) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path 'DC=corp,DC=local' -ProtectedFromAccidentalDeletion:$false
        Write-Host "[dc-baseline] created OU=$ou"
    }
}

$seedUsers = @(
    @{ name='alice';   ou='Corp';    group='Domain Users' },
    @{ name='bob';     ou='Corp';    group='Domain Users' },
    @{ name='carol';   ou='Corp';    group='Domain Users' },
    @{ name='dave';    ou='IT';      group='Domain Users' },
    @{ name='eve';     ou='IT';      group='Domain Users' },
    @{ name='svc_sql'; ou='Service'; group='Domain Users' },
    @{ name='svc_web'; ou='Service'; group='Domain Users' },
    @{ name='svc_bkp'; ou='Service'; group='Domain Users' }
)

foreach ($u in $seedUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.name)'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
          -Name $u.name `
          -SamAccountName $u.name `
          -AccountPassword (ConvertTo-SecureString $adminPassword -AsPlainText -Force) `
          -Path "OU=$($u.ou),DC=corp,DC=local" `
          -Enabled $true `
          -PasswordNeverExpires $true
        Write-Host "[dc-baseline] created user=$($u.name) ou=$($u.ou)"
    }
}

# --- 2. health check ---
Write-Host "[dc-baseline] repadmin /showrepl"
repadmin /showrepl | Out-Null
Write-Host "[dc-baseline] dcdiag /test:replications"
dcdiag /test:replications /q

Write-Host "[dc-baseline] COMPLETE"
