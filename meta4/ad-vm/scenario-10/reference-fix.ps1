# meta4/ad-vm/scenario-10/reference-fix.ps1
# Reference remediation for ADCS ESC6.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# EDITF_ATTRIBUTESUBJECTALTNAME2 makes the CA honour a subject alternative
# name supplied in the request, on ANY template. That turns every enrollable
# template into ESC1: request a certificate, name Administrator in the SAN,
# authenticate as them. Clearing the flag is the documented fix (MS ADV).
#
# CertSvc must be restarted for the policy-module flag to take effect --
# reference-fix-norestart.ps1 deliberately omits that, which is proof gate 4.

$ErrorActionPreference = 'Stop'

& certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "[fix-10] certutil -setreg returned $LASTEXITCODE" }

Restart-Service CertSvc -Force

# Service status is not readiness: CertSvc reports Running before its RPC
# interface answers, and certutil then fails with RPC_S_SERVER_UNAVAILABLE.
$deadline = (Get-Date).AddSeconds(180)
$ready = $false
while ((Get-Date) -lt $deadline) {
    if ((Get-Service CertSvc).Status -eq 'Running') {
        & certutil -ping 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    Start-Sleep -Seconds 5
}
if (-not $ready) { throw '[fix-10] CertSvc did not answer certutil -ping after restart' }

# Verify the flag is genuinely cleared rather than trusting the write.
$flags = (& certutil -getreg policy\EditFlags 2>&1 | Out-String)
if ($flags -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
    throw '[fix-10] EDITF_ATTRIBUTESUBJECTALTNAME2 is still set'
}

Write-Host '[fix-10] EDITF_ATTRIBUTESUBJECTALTNAME2 cleared and CertSvc restarted'
Write-Host '[fix-10] COMPLETE'
