# meta3/windows-vm/scenario-11-smb-signing/solution.ps1
# REFERENCE remediation (proves solvability). Run INSIDE the VM. On a real VM
# this genuinely makes the live server require signing, so the post-fix SMB2
# NEGOTIATE returns SecurityMode with the "required" bit and verify-poc passes.
$ErrorActionPreference = 'Stop'

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
Set-ItemProperty -Path $regPath -Name RequireSecuritySignature -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name EnableSecuritySignature  -Value 1 -Type DWord

Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false

Restart-Service -Name LanmanServer -Force

Write-Host "[solution-11] SMB signing required; LanmanServer restarted"
