# meta4/ad-vm/scenario-01/verify-service.ps1
# PASS (exit 0) iff the legacy certificate-authentication path is still viable.
#
# THIS IS WHAT MAKES SCENARIO-01 A COMPENSATING-CONTROL SCENARIO.
#
# The finding is a spoofable explicit certificate mapping. Two "fixes" would
# stop the PoC while destroying the thing the mapping exists for, and both are
# rejected here:
#
#   * StrongCertificateBindingEnforcement = 2 (Full Enforcement). This is the
#     textbook answer and it is UNAVAILABLE in this environment: the legacy
#     line-of-business application authenticates with certificates issued
#     before szOID_NTDS_CA_SECURITY_EXT existed, and Full Enforcement refuses
#     any certificate lacking that SID extension. Turning it on locks the
#     application out of the domain.
#
#   * Deleting altSecurityIdentities outright. The application has no
#     password-based path; the mapping IS how it authenticates.
#
# So the acceptable remediation is a compensating control: stay in
# Compatibility mode, keep a mapping, and make that mapping unspoofable by
# binding it to a specific key instead of to an email address. Microsoft's
# strong forms are X509IssuerSerialNumber (<I>...<SR>...), X509SKI and
# X509SHA1PublicKey.
#
# This deliberately does NOT assert that the mapping is strong. That property
# IS the vulnerability, and verify-poc.sh grades it behaviourally; asserting it
# here too would let a scenario pass on the service check alone and would make
# the two checks agree by construction rather than by evidence.

$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory

    $TargetUser = 'legacyops'
    $kdc = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'

    $mode = (Get-ItemProperty -Path $kdc -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
    if ($null -eq $mode) { $mode = 1 }   # absent behaves as Compatibility on this build
    if ($mode -eq 2) {
        throw ("StrongCertificateBindingEnforcement=2 (Full Enforcement) locks out the legacy " +
               "application's certificates, which carry no SID extension. That is not an available " +
               "remediation here -- bind the mapping strongly instead.")
    }

    $u = Get-ADUser -Identity $TargetUser -Properties altSecurityIdentities, Enabled -ErrorAction Stop
    if (-not $u)         { throw "$TargetUser does not exist -- deleting the account is not a remediation" }
    if (-not $u.Enabled) { throw "$TargetUser is disabled -- the legacy application could not authenticate" }

    $maps = @($u.altSecurityIdentities | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($maps.Count -eq 0) {
        throw ("$TargetUser has no altSecurityIdentities mapping. The legacy application authenticates " +
               "by certificate only, so removing the mapping breaks it -- replace it, do not delete it.")
    }

    Write-Host "[verify-service-01] $TargetUser enabled, $($maps.Count) certificate mapping(s) present"
    Write-Host "[verify-service-01] KDC binding mode $mode -- legacy certificates still accepted"
    Write-Host '[verify-service-01] service HEALTHY'
    exit 0
}
catch {
    Write-Error "[verify-service-01] $_"; exit 1
}
