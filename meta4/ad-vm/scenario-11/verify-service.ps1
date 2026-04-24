# meta4/ad-vm/scenario-11/verify-service.ps1
# PASS (exit 0) iff CertSvc is reachable AND a real cert can still be enrolled
# against the built-in User template. Web Enrollment is NOT part of the core
# service contract -- only the CA service itself must remain functional.

$ErrorActionPreference = 'Stop'
try {
    & certutil -ping | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certutil -ping exit=$LASTEXITCODE" }

    # Behavioural enrollment against the built-in User template. If the CA
    # is broken, this throws. Discard the resulting cert.
    $tmp = New-Item -ItemType Directory -Force -Path "C:\meta4-setup\svc-probe-11"
    $req = Join-Path $tmp "req.inf"
    @'
[NewRequest]
Subject="CN=svc-probe-11"
KeyLength=2048
KeyUsage=0xa0
MachineKeySet=False
RequestType=PKCS10
[RequestAttributes]
CertificateTemplate=User
'@ | Out-File -FilePath $req -Encoding ascii

    $csr = Join-Path $tmp "req.csr"
    $cer = Join-Path $tmp "out.cer"
    & certreq -new -q $req $csr | Out-Null
    & certreq -submit -q -config "corp-ca01.corp.local\corp-ca01-CA" $csr $cer | Out-Null

    if (-not (Test-Path $cer) -or (Get-Item $cer).Length -lt 100) {
        throw "CA did not issue a certificate on behalf of the User template"
    }
    Write-Host "[verify-service-11] CertSvc + legit User enrollment OK - service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-11] $_"
    exit 1
}
