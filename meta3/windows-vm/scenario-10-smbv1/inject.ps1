# meta3/windows-vm/scenario-10-smbv1/inject.ps1
# Introduces the vuln on the hardened baseline: re-enable the SMBv1 server
# dialect so the box is LIVE-vulnerable -- a raw SMB1 NEGOTIATE against 445 is
# then answered with an SMB1 dialect.
#
# Runs INSIDE the VM (via AutomatedLab Invoke-LabCommand, or the SSH bridge).
#
# TWO PASSES, because one is not enough. Windows registers the srv service
# (the SMB 1.x server driver) only while booting: enabling the SMB1Protocol
# optional feature with -NoRestart stages the driver but does not create the
# service. Until it exists, Set-SmbServerConfiguration -EnableSMB1Protocol
# $true fails with Windows System Error 1243, "The specified service does not
# exist" -- MEASURED on META3WIN, where the single-pass version of this script
# printed "EnableSMB1Protocol=False ... LIVE-vulnerable" and handed back a box
# whose SMB1 was still off. The scenario did not inject its own vulnerability.
#
# So pass 1 stages the feature and drops a .reboot-required sentinel;
# lab/Invoke-Scenario.ps1 reboots the VM and runs this script again; pass 2
# flips the dialect on and refuses to return unless SMB1 is genuinely serving.

$ErrorActionPreference = 'Stop'

$sentinel = Join-Path $PSScriptRoot '.reboot-required'
$paramKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

function Test-Smb1ServiceRegistered {
    return [bool](Get-Service -Name srv -ErrorAction SilentlyContinue)
}

function Wait-Smb445Listening {
    param([int] $TimeoutSeconds = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}

Write-Host "[inject-10] enabling SMBv1 server protocol"

# --- staged on both passes; idempotent ---
$feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($feature.State -ne 'Enabled') {
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    Write-Host "[inject-10] SMB1Protocol optional feature enabled (was $($feature.State))"
} else {
    Write-Host "[inject-10] SMB1Protocol optional feature already Enabled"
}

# Persist the dialect switch. This is the value Set-SmbServerConfiguration
# writes; setting it directly means the reboot in between already comes up with
# SMB1 on rather than needing a second service bounce.
Set-ItemProperty -Path $paramKey -Name 'SMB1' -Value 1 -Type DWord

# --- pass 1: the driver is not registered yet, so ask for the reboot ---
if (-not (Test-Smb1ServiceRegistered)) {
    New-Item -ItemType File -Path $sentinel -Force | Out-Null
    Write-Host "[inject-10] srv (SMB 1.x server) is not a registered service yet - REBOOT REQUIRED"
    Write-Host "[inject-10] wrote $sentinel; the lab driver reboots this VM and re-runs inject.ps1"
    exit 0
}

# --- pass 2: srv exists, so the canonical switch works ---
#
# Every step here is conditional because this script MUST be safe to run twice.
# AutomatedLab re-runs any Invoke-LabCommand scriptblock that returns no
# objects (see the comment in lab/Invoke-Scenario.ps1), and an unconditional
# Restart-Service on the second pass hits "Time out has expired" while the
# first bounce is still settling -- which failed the whole inject even though
# the vulnerability was already live.
$cfg = Get-SmbServerConfiguration
if (-not $cfg.EnableSMB1Protocol) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -Confirm:$false
    Restart-Service -Name LanmanServer -Force
}
if ((Get-Service -Name srv).Status -ne 'Running') { Start-Service -Name srv }

if (-not (Wait-Smb445Listening)) {
    throw "[inject-10] TCP/445 never came back after enabling SMB1 - refusing to hand back a half-injected host"
}

# --- refuse to return unless the vulnerability is actually live ---
$cfg = Get-SmbServerConfiguration
$srv = Get-Service -Name srv
if (-not $cfg.EnableSMB1Protocol) {
    throw "[inject-10] EnableSMB1Protocol is still False after the reboot pass - inject did NOT introduce the vulnerability"
}
if ($srv.Status -ne 'Running') {
    throw "[inject-10] srv (SMB 1.x server) is $($srv.Status), not Running - SMB1 would not be served"
}

Remove-Item -Path $sentinel -Force -ErrorAction SilentlyContinue
Write-Host "[inject-10] EnableSMB1Protocol=$($cfg.EnableSMB1Protocol); srv=$($srv.Status); 445 listening - LIVE-vulnerable"
