# meta4/ad-vm/scenario-10/inject.ps1
# Sets EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA, which makes the CA honor
# user-supplied subjectAltName attributes on ANY template. With this flag,
# any low-priv user can enrol in even the built-in User template and
# request -upn=administrator@corp.local; the CA puts that UPN into the SAN
# and issues. Subsequent PKINIT auth recovers Administrator's NT hash.

$ErrorActionPreference = 'Stop'

& certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -setreg returned $LASTEXITCODE" }

Restart-Service CertSvc -Force
# certutil -ping warm-up so the next probe sees a ready CA.
& certutil -ping | Out-Null

Write-Host "[inject-10] EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA -- ESC6 open"
