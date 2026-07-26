# meta4/ad-vm/scenario-13/reference-fix-norestart.ps1
# PROOF GATE 4 FIXTURE -- the config-only test.
#
# Writes the correct registry values but does NOT touch the running SMB
# server. The live service still does not require signing, so the PoC MUST
# still detect an unsigned-capable server (exit 1).
#
# If the PoC passes after this, it is reading the registry rather than probing
# the actual SMB negotiation -- which is exactly the defect the audit found in
# this scenario, where the check greps an nmap flag rather than attempting a
# relay.

$ErrorActionPreference = 'Stop'

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
Set-ItemProperty -Path $regPath -Name RequireSecuritySignature -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name EnableSecuritySignature  -Value 1 -Type DWord

Write-Host '[fix-13-norestart] registry set; running SMB server deliberately left unchanged'
