# All-in-one bootstrap task. Runs as SYSTEM via the AtStartup scheduled task
# registered by 01-register-dc-bootstrap.ps1. Must not depend on a WinRM
# session — Install-ADDSForest destroys the local SAM mid-run, which would
# 401 any concurrent WinRM-driven provisioner.
#
# Order matters:
#   1. Install-ADDSForest -NoRebootOnCompletion (SAM destroyed here)
#   2. Wait for AD Web Services (~30-60s after Install returns)
#   3. Add OPS\vagrant to Domain Admins   ← unblocks future WinRM auth
#   4. Run seed.ps1 (creates rogue DA, kerberoastable svc, etc.)
#   5. Install OpenSSH Server + bridge pubkey + sshd_config fix
#   6. Scrub answer key from VM
#   7. Write BOOTSTRAP_COMPLETE marker, unregister task
# No reboot needed — Install-ADDSForest's effects are live without one once
# AD Web Services come up, and OpenSSH starts cleanly post-install.

$ErrorActionPreference = "Stop"
$setupDir = "C:\hs13-setup"
$marker   = Join-Path $setupDir "BOOTSTRAP_COMPLETE"
$log      = Join-Path $setupDir "bootstrap.log"
function Log($m) { "[$(Get-Date -Format s)] $m" | Add-Content $log }

if (Test-Path $marker) {
    Log "marker already present; nothing to do"
    exit 0
}

Log "hs13-bootstrap fired (all-in-one)"

$roles   = Get-Content C:\ProgramData\sysrepair\roles.json | ConvertFrom-Json
$domain  = $roles.domain_fqdn
$netbios = $roles.domain_netbios
$dsrm    = $roles.dsrm_password

# --- Phase A: Install-ADDSForest --------------------------------------------
$ntdsPresent = [bool](Get-Service -Name NTDS -ErrorAction SilentlyContinue)
if (-not $ntdsPresent) {
    Log "Phase A: Install-ADDSForest"
    try {
        Install-ADDSForest `
          -DomainName $domain `
          -DomainNetbiosName $netbios `
          -SafeModeAdministratorPassword (ConvertTo-SecureString $dsrm -AsPlainText -Force) `
          -ForestMode WinThreshold `
          -DomainMode WinThreshold `
          -InstallDns:$true `
          -NoRebootOnCompletion:$true `
          -Force:$true | Out-Null
        Log "Install-ADDSForest returned"
    } catch {
        Log "Install-ADDSForest ERROR: $_"
        throw
    }
} else {
    Log "NTDS already present; skipping Install-ADDSForest"
}

# --- Wait for AD Web Services to be query-ready -----------------------------
Log "waiting for AD Web Services"
$ready = $false
$tries = 0
while ($tries -lt 120) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        if ((Get-ADDomain -ErrorAction Stop).DNSRoot -eq $domain) {
            $ready = $true; break
        }
    } catch { }
    Start-Sleep -Seconds 5
    $tries++
}
if (-not $ready) { throw "AD Web Services did not come up within 10 min" }
Log "AD Web Services ready after $($tries*5)s"

# --- Phase B: grant OPS\vagrant Domain Admin --------------------------------
Log "Phase B: granting $netbios\vagrant Domain Admin"
try {
    $inDA = $false
    try {
        $inDA = [bool](Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop |
                       Where-Object { $_.SamAccountName -eq "vagrant" })
    } catch { }
    if (-not $inDA) {
        Add-ADGroupMember -Identity "Domain Admins" -Members vagrant
        Log "added $netbios\vagrant to Domain Admins"
    }
} catch {
    Log "DA grant ERROR: $_"
    throw
}

# --- Run seed.ps1 -----------------------------------------------------------
$seedSrc = Join-Path $setupDir "seed.ps1"
if (Test-Path $seedSrc) {
    Log "running seed.ps1"
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $seedSrc *>> $log
        Log "seed.ps1 finished"
    } catch {
        Log "seed.ps1 ERROR: $_"
        throw
    }
} else {
    throw "$seedSrc not found"
}

# --- Install OpenSSH Server + bridge pubkey + sshd_config fix ---------------
Log "installing OpenSSH Server"
try {
    $cap = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
    if ($cap.State -ne "Installed") {
        Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    }
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd -ErrorAction SilentlyContinue

    if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    }

    $pubKeyPath = Join-Path $setupDir "vagrant_key.pub"
    $bridgePub  = (Get-Content $pubKeyPath -Raw).Trim()
    if (-not $bridgePub) { throw "$pubKeyPath is empty" }
    $authKey = "C:\ProgramData\ssh\administrators_authorized_keys"
    Set-Content -Path $authKey -Value $bridgePub -Encoding ascii -Force -NoNewline
    icacls $authKey /inheritance:r /grant "Administrators:F" "SYSTEM:F" | Out-Null

    # Microsoft's stock sshd_config ships `Match Group administrators` without
    # the AuthorizedKeysFile body — sshd then ignores administrators_authorized_keys.
    $sshdConfig = "C:\ProgramData\ssh\sshd_config"
    $cfg = Get-Content $sshdConfig -Raw
    if ($cfg -notmatch 'AuthorizedKeysFile\s+__PROGRAMDATA__/ssh/administrators_authorized_keys') {
        Add-Content -Path $sshdConfig `
            -Value "       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys" `
            -Encoding ascii
        Restart-Service sshd
    }
    Log "OpenSSH ready"
} catch {
    Log "OpenSSH ERROR: $_"
    throw
}

# --- Anti-contamination: scrub answer key -----------------------------------
Remove-Item "C:\ProgramData\sysrepair\verify.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\ProgramData\sysrepair\roles.json" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Users\vagrant\provisioning"      -Recurse -Force -ErrorAction SilentlyContinue
Log "answer key scrubbed"

# --- Done -------------------------------------------------------------------
New-Item -ItemType File -Path $marker -Force | Out-Null
schtasks /Delete /TN "hs13-bootstrap" /F | Out-Null
Log "BOOTSTRAP_COMPLETE; hs13-bootstrap unregistered; done"
