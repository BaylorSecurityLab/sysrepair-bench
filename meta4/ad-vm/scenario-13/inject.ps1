# meta4/ad-vm/scenario-13/inject.ps1
# Disables SMB signing requirement on DC's LanManServer.

$ErrorActionPreference = 'Stop'

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'

Set-ItemProperty -Path $regPath -Name RequireSecuritySignature -Value 0 -Type DWord
Set-ItemProperty -Path $regPath -Name EnableSecuritySignature  -Value 1 -Type DWord

# Also reflect via SMB cmdlet for immediate effect without reboot.
Set-SmbServerConfiguration -RequireSecuritySignature $false -Confirm:$false -Force

Write-Host "[inject-13] SMB signing requirement disabled on DC"
