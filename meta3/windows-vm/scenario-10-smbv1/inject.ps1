# meta3/windows-vm/scenario-10-smbv1/inject.ps1
# Introduces the vuln on the hardened baseline: re-enable the SMBv1 server
# dialect and restart LanmanServer so the box is LIVE-vulnerable — a raw SMB1
# NEGOTIATE against 445 will now be answered with an SMB1 dialect.
#
# Runs INSIDE the VM (via AutomatedLab Invoke-LabCommand, or the SSH bridge).

$ErrorActionPreference = 'Stop'

Write-Host "[inject-10] enabling SMBv1 server protocol"

# Canonical server-side switch. On a full Server 2019 the SMB1 optional
# feature is present; enable it too so the driver is available, then flip the
# server config value that Set-SmbServerConfiguration -EnableSMB1Protocol writes.
try {
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    Write-Host "[inject-10] SMB1Protocol optional feature enabled"
} catch {
    Write-Host "[inject-10] optional-feature enable skipped/failed: $_"
}

Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -Confirm:$false

# Persist the registry value directly too (belt and suspenders).
$paramKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty -Path $paramKey -Name 'SMB1' -Value 1 -Type DWord

# Restart LanmanServer (and dependents) so the live listener honours SMB1 now.
Restart-Service -Name LanmanServer -Force

$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
Write-Host "[inject-10] EnableSMB1Protocol=$smb1; LanmanServer restarted — LIVE-vulnerable"
