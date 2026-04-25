# meta4/ad-vm/scenario-05/verify-service.ps1
# PASS (exit 0) iff corp-ca01's domain secure channel is healthy.

$ErrorActionPreference = 'Stop'
try {
    $sec  = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $sec)
    $ok = Test-ComputerSecureChannel -Server corp-dc01 -Credential $cred
    if (-not $ok) { throw "Test-ComputerSecureChannel returned false" }
    Write-Host "[verify-service-05] CA secure channel to DC healthy -- service HEALTHY"
    exit 0
}
catch {
    Write-Error "[verify-service-05] $_"; exit 1
}
