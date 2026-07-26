# meta4/ad-vm/provision/ca-postinstall.ps1
# Post-install configuration for the Enterprise Root CA. Idempotent.
#
# Ported from the retired ca-baseline.ps1. Domain join, ADCS role install and
# DNS configuration are all gone -- AutomatedLab's CaRoot role handles them.
#
# CRL VALIDITY. Cold checkpoints freeze certificate validity windows. Once a
# baseline ages past the CRL's period, every restore begins with an expired
# CRL -- and a certificate-validation failure is indistinguishable from "the
# vulnerability was fixed", so scenarios 07-11 would drift toward false PASSes
# that get worse the older the baseline gets. A 10-year CRL removes the drift.

$ErrorActionPreference = 'Stop'

$caCommonName = 'corp-ca01-CA'

Write-Host '[ca] verifying CA identity'
$actual = (certutil -getreg CA\CommonName | Out-String)
if ($actual -notmatch [regex]::Escape($caCommonName)) {
    throw @"
[ca] expected CommonName '$caCommonName' but found:
$actual
Scenarios 07-10 pass this name to ``certipy-ad -ca``. A CA's common name cannot
be changed after installation, so this requires rebuilding the CA with
CACommonName pinned in lab/SysRepairLab.ps1.
"@
}

Write-Host '[ca] extending CRL validity to 10 years'
certutil -setreg CA\CRLPeriod 'Years'      | Out-Null
certutil -setreg CA\CRLPeriodUnits 10      | Out-Null
certutil -setreg CA\CRLDeltaPeriod 'Days'  | Out-Null
certutil -setreg CA\CRLDeltaPeriodUnits 0  | Out-Null

Write-Host '[ca] restarting CertSvc to apply CRL settings'
Restart-Service CertSvc -Force

# Service status is NOT readiness. CertSvc reports Running well before its RPC
# interface accepts calls, so certutil fails with 0x800706BA
# (RPC_S_SERVER_UNAVAILABLE, -2147023174) if we proceed on Status alone.
# Poll the interface itself.
$deadline = (Get-Date).AddSeconds(180)
$ready = $false
while ((Get-Date) -lt $deadline) {
    if ((Get-Service CertSvc).Status -eq 'Running') {
        certutil -ping 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    Start-Sleep -Seconds 5
}
if (-not $ready) {
    throw '[ca] CertSvc did not answer certutil -ping within 180s of restarting'
}
Write-Host '[ca] CertSvc RPC interface is answering'

Write-Host '[ca] publishing a fresh CRL'
# Retry: the first CRL publish immediately after a restart can still race the
# CA's own initialisation even once ping answers.
$published = $false
for ($i = 1; $i -le 6; $i++) {
    certutil -CRL 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $published = $true; break }
    Write-Host "[ca] CRL publish attempt $i returned $LASTEXITCODE; retrying"
    Start-Sleep -Seconds 10
}
if (-not $published) { throw "[ca] certutil -CRL failed after 6 attempts (last exit code $LASTEXITCODE)" }

Write-Host '[ca] verifying the CRL period actually took'
$unitsRaw = (certutil -getreg CA\CRLPeriodUnits | Out-String)
$periodRaw = (certutil -getreg CA\CRLPeriod | Out-String)

# certutil prints DWORDs as `= a (10)` -- hex first, decimal in parentheses --
# so a naive `=\s*(\d+)` match cannot read any value of 10 or more.
$units = if ($unitsRaw -match 'CRLPeriodUnits\s+REG_DWORD\s*=\s*\S+\s+\((\d+)\)') { [int]$Matches[1] } else { -1 }
$period = if ($periodRaw -match 'CRLPeriod\s+REG_SZ\s*=\s*(\w+)') { $Matches[1] } else { 'unknown' }

if ($period -ne 'Years' -or $units -lt 10) {
    throw "[ca] CRL period did not take: got $units $period, expected >=10 Years"
}
Write-Host "[ca] CRL period confirmed: $units $period"

Write-Host '[ca] certutil -ping'
certutil -ping | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "[ca] certutil -ping failed with exit code $LASTEXITCODE"
}

Write-Host '[ca] COMPLETE'
