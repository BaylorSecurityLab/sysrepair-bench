# meta3/windows-vm/provision/baseline.ps1
# Baseline provisioning for the standalone Server 2019 member (META3WIN).
# Runs ONCE inside the VM after Install-Lab (via Invoke-LabCommand, or manually).
#
# Leaves the box in a HARDENED baseline so each scenario's inject.ps1 introduces
# exactly one live vuln:
#   * OpenSSH server installed + running   (the scorer's SSH bridge, port 22)
#   * SMB file service (LanmanServer) up, 445 listening
#   * RDP (TermService) up, 3389 listening
#   * SMB1 OFF, SMB signing REQUIRED, RDP NLA ON (UserAuthentication=1, SecurityLayer=2)
#   * a deliberately weak local admin account (the "weak admin")
#
# Idempotent: safe to re-run.
[CmdletBinding()]
param(
    # Public key the eval bridge container uses to SSH in. Optional at author
    # time; supply the contents of build/bridge_key.pub at deploy time.
    [string] $BridgePubKey = '',

    # Weak admin the scenarios assume exists.
    [string] $WeakAdminUser = 'svc_admin',
    [string] $WeakAdminPass = 'Passw0rd!'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. OpenSSH server (bridge). Capability install, default shell = PowerShell.
# ---------------------------------------------------------------------------
Write-Host "[baseline] installing OpenSSH Server"
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String -Force | Out-Null

if (-not (Get-NetFirewallRule -Name 'sshd-22' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'sshd-22' -DisplayName 'OpenSSH Server (sshd)' `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

# Install the bridge public key into the administrators authorized_keys file
# (the location sshd uses for members of the Administrators group).
if ($BridgePubKey) {
    $adminKeys = "$env:ProgramData\ssh\administrators_authorized_keys"
    Set-Content -Path $adminKeys -Value $BridgePubKey -Encoding ascii
    icacls $adminKeys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
    Write-Host "[baseline] bridge public key installed"
} else {
    Write-Warning "[baseline] no -BridgePubKey supplied; SSH bridge key not installed yet"
}

# ---------------------------------------------------------------------------
# 2. Weak admin account.
# ---------------------------------------------------------------------------
Write-Host "[baseline] creating weak admin '$WeakAdminUser'"
$secpw = ConvertTo-SecureString $WeakAdminPass -AsPlainText -Force
if (-not (Get-LocalUser -Name $WeakAdminUser -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $WeakAdminUser -Password $secpw -PasswordNeverExpires -AccountNeverExpires | Out-Null
} else {
    Set-LocalUser -Name $WeakAdminUser -Password $secpw
}
Add-LocalGroupMember -Group 'Administrators' -Member $WeakAdminUser -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 3. SMB file service up + HARDENED (SMB1 off, signing required).
# ---------------------------------------------------------------------------
Write-Host "[baseline] hardening SMB (SMB1 off, signing required)"
Set-Service -Name LanmanServer -StartupType Automatic
Start-Service LanmanServer -ErrorAction SilentlyContinue

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false
try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null } catch {}

$smbParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
Set-ItemProperty -Path $smbParams -Name 'SMB1' -Value 0 -Type DWord
Set-ItemProperty -Path $smbParams -Name 'RequireSecuritySignature' -Value 1 -Type DWord
Set-ItemProperty -Path $smbParams -Name 'EnableSecuritySignature'  -Value 1 -Type DWord

if (-not (Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True')) {
    Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue
}
Restart-Service -Name LanmanServer -Force

# ---------------------------------------------------------------------------
# 4. RDP up + HARDENED (NLA on, TLS required).
# ---------------------------------------------------------------------------
Write-Host "[baseline] enabling + hardening RDP (NLA on, TLS required)"
$rdpTcp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$tsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

Set-ItemProperty -Path $tsBase -Name 'fDenyTSConnections' -Value 0 -Type DWord
Set-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -Value 1 -Type DWord
Set-ItemProperty -Path $rdpTcp -Name 'SecurityLayer'      -Value 2 -Type DWord
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
Set-Service -Name TermService -StartupType Automatic
Start-Service TermService -ErrorAction SilentlyContinue

Write-Host "[baseline] COMPLETE — hardened baseline ready for per-scenario inject"
