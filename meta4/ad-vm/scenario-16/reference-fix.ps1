# meta4/ad-vm/scenario-16/reference-fix.ps1
# Reference remediation for the Print Spooler exposure (scenario-16).
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# IMPORTANT -- THIS SCENARIO HAS A KNOWN DESIGN MISMATCH.
#
# threat.md describes PrintNightmare (CVE-2021-34527, RpcAddPrinterDriverEx)
# and lists the KB5005010 Point-and-Print hardening as the remediation. But
# verify-poc.sh exercises `impacket-spoolsample`, which is MS-RPRN PrinterBug
# COERCION -- a different primitive. Setting
# RestrictDriverInstallationToAdministrators=1 correctly blocks
# PrintNightmare and does NOT stop PrinterBug, so two of the three documented
# remediations cannot make the PoC pass.
#
# This fixture therefore applies BOTH:
#   * the Point-and-Print hardening, which is the correct fix for the
#     vulnerability threat.md actually describes; and
#   * stopping and disabling the Spooler, which is what the PoC as written
#     requires and is also KB5005010's own guidance for DCs, where the
#     Spooler has no legitimate role.
#
# Stopping the Spooler on a DC is legitimate hardening, not a check-defeating
# hack -- scenario-16's own verify-service.ps1 explicitly accepts
# "Stopped + Disabled" as healthy. The scenario should still be reworked so
# threat.md and the PoC describe the same vulnerability; recorded rather than
# papered over.

$ErrorActionPreference = 'Stop'

# 1. Point-and-Print hardening (the PrintNightmare fix threat.md describes).
$papKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
if (-not (Test-Path $papKey)) { New-Item -Path $papKey -Force | Out-Null }
Set-ItemProperty -Path $papKey -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -Type DWord
Set-ItemProperty -Path $papKey -Name 'NoWarningNoElevationOnInstall' -Value 0 -Type DWord
Set-ItemProperty -Path $papKey -Name 'UpdatePromptSettings' -Value 0 -Type DWord

# 2. Remove the Spooler attack surface entirely (KB5005010 guidance for DCs,
#    and what the PoC actually tests).
Stop-Service Spooler -Force -ErrorAction SilentlyContinue
Set-Service Spooler -StartupType Disabled

$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    if ((Get-Service Spooler).Status -eq 'Stopped') { break }
    Start-Sleep -Seconds 3
}

$svc = Get-Service Spooler
if ($svc.Status -ne 'Stopped') { throw '[fix-16] Spooler did not stop' }
if ((Get-Service Spooler).StartType -ne 'Disabled') { throw '[fix-16] Spooler is not disabled' }

$pap = Get-ItemProperty -Path $papKey
if ($pap.RestrictDriverInstallationToAdministrators -ne 1) {
    throw '[fix-16] RestrictDriverInstallationToAdministrators is not 1'
}

Write-Host '[fix-16] Point-and-Print hardened and Spooler stopped + disabled'
Write-Host '[fix-16] COMPLETE'
