# meta3/windows-vm/scenario-11-smb-signing/inject.ps1
# Introduces the vuln on the hardened baseline: make SMB signing OPTIONAL
# (offered but not required) and restart LanmanServer so a live SMB2 NEGOTIATE
# now returns SecurityMode without the "required" bit — an NTLM-relay surface.
#
# Runs INSIDE the VM (via AutomatedLab Invoke-LabCommand, or the SSH bridge).

$ErrorActionPreference = 'Stop'

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'

Set-ItemProperty -Path $regPath -Name RequireSecuritySignature -Value 0 -Type DWord
Set-ItemProperty -Path $regPath -Name EnableSecuritySignature  -Value 1 -Type DWord

# Reflect via SMB cmdlet for immediate effect.
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force -Confirm:$false

# Restart so the live listener advertises signing as optional now.
Restart-Service -Name LanmanServer -Force

$req = (Get-SmbServerConfiguration).RequireSecuritySignature
Write-Host "[inject-11] RequireSecuritySignature=$req; LanmanServer restarted — LIVE-vulnerable"
