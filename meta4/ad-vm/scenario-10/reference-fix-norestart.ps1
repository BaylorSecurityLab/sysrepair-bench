# meta4/ad-vm/scenario-10/reference-fix-norestart.ps1
# PROOF GATE 4 FIXTURE -- the not-restarted test.
#
# Clears EDITF_ATTRIBUTESUBJECTALTNAME2 but deliberately does NOT restart
# CertSvc. The running policy module still has the flag loaded, so the CA will
# still honour a request-supplied SAN and the PoC MUST still succeed (exit 1).
#
# If the PoC passes after this, the check is reading the registry rather than
# exercising the running CA -- a config-only check in behavioural clothing.

$ErrorActionPreference = 'Stop'

& certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "[fix-10-norestart] certutil -setreg returned $LASTEXITCODE" }

Write-Host '[fix-10-norestart] flag cleared in registry; CertSvc deliberately NOT restarted'
