# meta4/ad-vm/scenario-02/inject.ps1
# Resets ms-DS-MachineAccountQuota to the Windows default of 10. Any
# authenticated domain user can then create up to 10 computer accounts,
# which is the foothold step of the NoPac (CVE-2021-42278 + CVE-2021-42287)
# kill chain. The lab fixes the residual MAQ misconfig; the underlying
# CVEs are already patched in the base box.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

Set-ADDomain -Identity corp.local -Replace @{ 'ms-DS-MachineAccountQuota' = 10 }
Write-Host "[inject-02] ms-DS-MachineAccountQuota set to 10 (NoPac foothold present)"
