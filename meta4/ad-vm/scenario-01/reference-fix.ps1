# meta4/ad-vm/scenario-01/reference-fix.ps1
# Reference remediation for ESC14 -- a weak explicit certificate mapping.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees. Gates 2 and 3
# cannot be evaluated without it.
#
# THE OBVIOUS FIX IS DELIBERATELY NOT AVAILABLE. Setting
# StrongCertificateBindingEnforcement = 2 would stop the attack and lock the
# legacy application out of the domain, because its certificates predate
# szOID_NTDS_CA_SECURITY_EXT and carry no SID extension. verify-service.ps1
# fails that outcome. Deleting the mapping is rejected for the same reason:
# the application has no password-based path.
#
# The compensating control is to keep Compatibility mode and keep a mapping,
# while replacing the SPOOFABLE binding with one tied to a specific key.
# Microsoft's strong forms are:
#
#   X509IssuerSerialNumber   X509:<I>...<SR>...
#   X509SKI                  X509:<SKI>...
#   X509SHA1PublicKey        X509:<SHA1-PUKEY>...
#
# An email address (X509:<RFC822>) binds to a value anyone can put in a SAN;
# an issuer plus serial number binds to one issued certificate.
#
# The legacy application's certificate is represented here by a generated
# credential -- in a real environment this step is "re-issue the application's
# certificate and bind the mapping to it", not "invent a new one".

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$TargetUser = 'legacyops'

# --- the certificate the legacy application will present ---
$cert = New-SelfSignedCertificate `
    -Subject 'CN=legacy-lob-app,OU=Legacy,DC=corp,DC=local' `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyExportPolicy Exportable -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(2)

# --- build the X509IssuerSerialNumber mapping ---
#
# The serial number is reversed byte-wise relative to its display form. This is
# the step that is easy to get silently wrong: a malformed mapping does not
# error, it simply never matches, which looks like a successful fix while the
# legacy application quietly stops authenticating.
$issuer = $cert.Issuer
$serialBytes = $cert.GetSerialNumber()          # already little-endian
$serial = -join ($serialBytes | ForEach-Object { $_.ToString('x2') })

$strongMapping = "X509:<I>$issuer<SR>$serial"

Set-ADUser -Identity $TargetUser -Replace @{ altSecurityIdentities = $strongMapping }

# --- verify the mapping is strong AND still present ---
$u = Get-ADUser -Identity $TargetUser -Properties altSecurityIdentities
$maps = @($u.altSecurityIdentities | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($maps.Count -eq 0) {
    throw '[fix-01] the mapping was removed rather than replaced -- the legacy application would break'
}
foreach ($m in $maps) {
    if ($m -match '^X509:<RFC822>' -or $m -match '^X509:<S>' -or ($m -match '^X509:<I>' -and $m -notmatch '<SR>')) {
        throw "[fix-01] a weak mapping is still present: $m"
    }
}

# --- and that we did NOT take the forbidden shortcut ---
$kdc  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
$mode = (Get-ItemProperty -Path $kdc -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
if ($mode -eq 2) {
    throw '[fix-01] Full Enforcement was enabled; that breaks the legacy application and is not this remediation'
}

Write-Host "[fix-01] $TargetUser now mapped by X509IssuerSerialNumber, bound to one certificate"
Write-Host "[fix-01] Compatibility mode retained ($mode) so legacy certificates still authenticate"
Write-Host '[fix-01] COMPLETE'
