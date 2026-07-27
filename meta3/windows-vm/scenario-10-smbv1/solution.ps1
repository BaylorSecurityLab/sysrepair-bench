# meta3/windows-vm/scenario-10-smbv1/solution.ps1
# REFERENCE remediation (proves solvability during deploy+validate). Run INSIDE
# the VM. On a real VM this genuinely turns off the live SMB1 dialect, so the
# post-fix live probe returns "rejected" and verify-poc.ps1 passes.
$ErrorActionPreference = 'Stop'

# Disable the SMBv1 server dialect and remove the optional feature.
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
    -Name 'SMB1' -Value 0 -Type DWord
try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
} catch { Write-Host "[solution-10] optional-feature disable skipped: $_" }

# Restart the live listener so it stops answering SMB1 immediately.
Restart-Service -Name LanmanServer -Force

Write-Host "[solution-10] SMBv1 disabled; LanmanServer restarted"
