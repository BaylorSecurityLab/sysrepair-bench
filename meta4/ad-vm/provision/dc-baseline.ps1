# meta4/ad-vm/provision/dc-baseline.ps1
# Promotes to corp.local forest root, seeds directory with 25 users, 3 OUs, and groups.
# Idempotent: safe to re-run; exits 0 if already provisioned.

$ErrorActionPreference = 'Stop'

$domainName      = 'corp.local'
$netbiosName     = 'CORP'
$dsrmPassword    = ConvertTo-SecureString 'Vagrant1DSRM!' -AsPlainText -Force
$adminPassword   = 'Password1!'

# --- 0. idempotency guard ---
if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain -and
    (Get-ADDomain -ErrorAction SilentlyContinue) -and
    ((Get-ADDomain).DNSRoot -eq $domainName)) {
    Write-Host "[dc-baseline] already joined to $domainName, skipping promotion"
} else {
    Write-Host "[dc-baseline] installing AD DS role"
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

    # Stage a one-shot startup task to recreate the 'vagrant' principal as a
    # Domain User post-DCPROMO. The local 'vagrant' account is lost when the
    # machine becomes a DC; without a matching CORP\vagrant domain user,
    # vagrant-reload cannot reconnect and the second provisioning pass stalls.
    $setupDir = 'C:\meta4-setup'
    New-Item -ItemType Directory -Path $setupDir -Force | Out-Null
    $postScript = Join-Path $setupDir 'create-vagrant-da.ps1'

    $postBody = @'
$ErrorActionPreference = "Stop"
$log = "C:\meta4-setup\create-vagrant-da.log"
"[$(Get-Date -Format s)] starting post-DCPROMO user creation" | Add-Content $log

for ($i = 0; $i -lt 60; $i++) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Get-ADDomain -ErrorAction Stop | Out-Null
        "[$(Get-Date -Format s)] AD ready after $($i*10)s" | Add-Content $log
        break
    } catch {
        Start-Sleep -Seconds 10
    }
}

try {
    if (-not (Get-ADUser -Filter { SamAccountName -eq "vagrant" } -ErrorAction SilentlyContinue)) {
        New-ADUser -Name vagrant `
          -SamAccountName vagrant `
          -AccountPassword (ConvertTo-SecureString "vagrant" -AsPlainText -Force) `
          -Enabled $true `
          -PasswordNeverExpires $true
        Add-ADGroupMember -Identity "Domain Admins" -Members vagrant
        "[$(Get-Date -Format s)] created CORP\vagrant in Domain Admins" | Add-Content $log
    } else {
        "[$(Get-Date -Format s)] CORP\vagrant already exists" | Add-Content $log
    }
    Set-Service WinRM -StartupType Automatic
    Start-Service WinRM
    "[$(Get-Date -Format s)] WinRM re-enabled + started" | Add-Content $log
    schtasks /Delete /TN "Meta4-PostDcPromo" /F | Out-Null
    schtasks /Delete /TN "Meta4-PostDcPromo-Rescue" /F 2>$null | Out-Null
    "[$(Get-Date -Format s)] tasks unregistered, done" | Add-Content $log
} catch {
    "[$(Get-Date -Format s)] ERROR: $_" | Add-Content $log
    # Safety: unconditionally re-enable WinRM so the VM stays reachable for diag.
    try { Set-Service WinRM -StartupType Automatic; Start-Service WinRM } catch {}
    throw
}
'@
    Set-Content -Path $postScript -Value $postBody -Encoding UTF8

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                   -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$postScript`""
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
                   -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                   -StartWhenAvailable -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'Meta4-PostDcPromo' `
      -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "[dc-baseline] registered Meta4-PostDcPromo startup task"

    # Safety net: force WinRM back on after 15 min regardless of primary task
    # outcome, so a failed post-DCPROMO user-creation doesn't strand the VM.
    # Use a wrapper .cmd on disk to dodge schtasks /TR quoting issues.
    $rescueCmd = Join-Path $setupDir 'winrm-rescue.cmd'
    Set-Content -Path $rescueCmd -Encoding ASCII -Value @'
@echo off
powershell.exe -NoProfile -Command "Set-Service WinRM -StartupType Automatic; Start-Service WinRM"
'@
    $rescueAction    = New-ScheduledTaskAction -Execute $rescueCmd
    $rescueTrigger   = New-ScheduledTaskTrigger -AtStartup
    $rescueTrigger.Delay = 'PT15M'
    $rescuePrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
                         -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'Meta4-PostDcPromo-Rescue' `
      -Action $rescueAction -Trigger $rescueTrigger -Principal $rescuePrincipal `
      -Settings $settings -Force | Out-Null
    Write-Host "[dc-baseline] registered Meta4-PostDcPromo-Rescue safety task"

    Write-Host "[dc-baseline] promoting to forest root of $domainName (no auto-reboot)"
    Install-ADDSForest `
      -DomainName $domainName `
      -DomainNetbiosName $netbiosName `
      -SafeModeAdministratorPassword $dsrmPassword `
      -ForestMode WinThreshold `
      -DomainMode WinThreshold `
      -InstallDns:$true `
      -NoRebootOnCompletion:$true `
      -Force:$true

    # Disable WinRM auto-start so the post-reboot startup task controls when
    # the listener comes up — only after CORP\vagrant exists, to prevent
    # vagrant-reload from racing in and getting a 401 as a now-gone local user.
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
