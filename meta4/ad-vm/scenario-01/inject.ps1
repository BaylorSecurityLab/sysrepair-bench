# meta4/ad-vm/scenario-01/inject.ps1
#
# ESC14 -- weak explicit certificate mapping (altSecurityIdentities).
#
# REPLACES the former Zerologon scenario, which could not be induced: the
# CVE-2020-1472 fix is in code, not configuration, so no registry state makes a
# current Server 2019 vulnerable again. See git history and the old INVALID.md.
#
# Creates a privileged account whose certificate mapping is SPOOFABLE, on a DC
# running certificate binding in Compatibility mode. Three pieces:
#
#  1. StrongCertificateBindingEnforcement = 1 (Compatibility). Full Enforcement
#     (2) became the default in February 2025, but a DC that must still accept
#     legacy certificates -- ones issued without the szOID_NTDS_CA_SECURITY_EXT
#     SID extension -- cannot be moved to 2 without breaking them. That
#     constraint is what makes this a COMPENSATING-CONTROL scenario, and
#     verify-service.ps1 enforces it.
#
#  2. legacyops, a Domain Admin, mapped by X509:<RFC822> -- an email address.
#     Microsoft classifies RFC822, IssuerSubject and SubjectOnly mappings as
#     WEAK precisely because the value is not bound to a key: anything able to
#     obtain a certificate carrying that email is accepted as the account.
#
#  3. Domain Users may enrol in the built-in User template, which copies the
#     requester's mail attribute into the certificate SAN -- and a user can
#     write their own mail, because SELF holds Write Personal-Information by
#     default.
#
# So alice sets her own mail to legacyops@corp.local, enrols normally, and the
# KDC maps the resulting certificate onto a Domain Admin.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$TargetUser = 'legacyops'
$TargetMail = 'legacyops@corp.local'

# --- 1. Compatibility mode on the KDC ---
$kdc = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
if (-not (Test-Path $kdc)) { New-Item -Path $kdc -Force | Out-Null }
Set-ItemProperty -Path $kdc -Name 'StrongCertificateBindingEnforcement' -Value 1 -Type DWord

# --- 2. the privileged account with a weak mapping ---
$u = Get-ADUser -Filter "SamAccountName -eq '$TargetUser'" -ErrorAction SilentlyContinue
if (-not $u) {
    New-ADUser -Name $TargetUser -SamAccountName $TargetUser `
        -UserPrincipalName $TargetMail `
        -AccountPassword (ConvertTo-SecureString 'L3gacy0ps!2026#svc' -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true `
        -Description 'Service account for the legacy line-of-business application'
}

if (-not (Get-ADGroupMember 'Domain Admins' | Where-Object { $_.SamAccountName -eq $TargetUser })) {
    Add-ADGroupMember -Identity 'Domain Admins' -Members $TargetUser
}

# The weak mapping. X509:<RFC822> binds on an email address, which is not
# unique to a key and can be claimed by anyone able to influence a SAN.
Set-ADUser -Identity $TargetUser -Replace @{ altSecurityIdentities = "X509:<RFC822>$TargetMail" }

# --- 3. the self-service delegation that makes the weak mapping reachable ---
#
# Users updating their own contact details is an ordinary delegation, and it is
# what turns a weak RFC822 mapping from a latent misconfiguration into a live
# privilege-escalation path. It is deliberately part of the SETUP, not the
# finding: the remediation is to bind the mapping to a key, not to stop users
# maintaining their own email address.
#
# It has to be granted explicitly. SELF does not hold Write
# Personal-Information on user objects in this domain -- measured, alice's own
# ldapmodify came back "Insufficient access" -- so assuming the documented
# default would have left the scenario unexploitable and looking remediated.
$alice = Get-ADUser -Identity alice -Properties mail
if ($alice.mail) { Set-ADUser -Identity alice -Clear mail }

$mailAttrGuid = [Guid]'bf967961-0de6-11d0-a285-00aa003049e2'   # schemaIDGUID of `mail`
$selfSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::SelfSid, $null)

$acl = Get-Acl "AD:$($alice.DistinguishedName)"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $selfSid,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $mailAttrGuid)
$acl.AddAccessRule($ace)
Set-Acl "AD:$($alice.DistinguishedName)" -AclObject $acl

# --- 4. the legacy template: no SID extension, email in the SAN ---
#
# WITHOUT THIS THE MAPPING IS NEVER CONSULTED. Certificates from this CA
# normally carry szOID_NTDS_CA_SECURITY_EXT, and the KDC resolves the SID in
# that extension first -- measured on the live lab, alice's certificate came
# back as
#     SAN UPN: 'alice@corp.local'
#     Security Extension SID: 'S-1-5-21-...-1105'   (alice)
# so it identified alice and altSecurityIdentities was irrelevant.
#
# CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) suppresses that extension, which
# is precisely why legacy templates carry it: certificates that must be
# consumed by systems predating the extension. A certificate with no SID forces
# the KDC to fall back to explicit mapping -- and the explicit mapping here is
# spoofable. The two together are the vulnerability.
$LegacyTemplate = 'LegacyAppAuth'
$configNC = (Get-ADRootDSE).configurationNamingContext
$tmplParent = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

$legacyAttrs = @{
    # CN from AD + email in the SAN. UPN is deliberately NOT included: the
    # RFC822 address must be the only identity the certificate asserts.
    'msPKI-Certificate-Name-Flag'   = 0x44000000
    'msPKI-Enrollment-Flag'         = 0x00080000   # NO_SECURITY_EXTENSION
    'msPKI-Private-Key-Flag'        = 0x10
    'msPKI-Template-Minor-Revision' = 1
    'msPKI-Template-Schema-Version' = 2
    'pKIExtendedKeyUsage'           = @('1.3.6.1.5.5.7.3.2')
    'msPKI-Certificate-Application-Policy' = @('1.3.6.1.5.5.7.3.2')
    'pKIKeyUsage'                   = [byte[]](0xa0)
    'msPKI-RA-Signature'            = 0
    'msPKI-Minimal-Key-Size'        = 2048
    'pKIDefaultKeySpec'             = 1
    'pKIMaxIssuingDepth'            = 0
    'pKIExpirationPeriod'           = [byte[]](0,0x40,0x39,0x87,0x2e,0xe1,0xfe,0xff)
    'pKIOverlapPeriod'              = [byte[]](0,0x80,0xa6,0x0a,0xff,0xde,0xff,0xff)
}

$existing = Get-ADObject -SearchBase $tmplParent -Filter "name -eq '$LegacyTemplate'" `
                         -Server corp-dc01 -ErrorAction SilentlyContinue
if (-not $existing) {
    # A schema-version-2 template needs an OID, revision and flags or the CA
    # answers CERTSRV_E_UNSUPPORTED_CERT_TYPE -- see scenario-07/08/09.
    $oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
    $forestArc = (Get-ADObject -Identity $oidContainer -Properties 'msPKI-Cert-Template-OID' `
                               -Server corp-dc01).'msPKI-Cert-Template-OID'
    if (-not $forestArc) { throw '[inject-01] cannot read the forest template OID arc' }
    $templateOid = '{0}.{1}.{2}' -f $forestArc, (Get-Random -Minimum 1000000 -Maximum 99999999),
                                                (Get-Random -Minimum 1000000 -Maximum 99999999)
    $oidName = "$LegacyTemplate-OID"
    if (-not (Get-ADObject -SearchBase $oidContainer -Filter "name -eq '$oidName'" `
                           -Server corp-dc01 -ErrorAction SilentlyContinue)) {
        New-ADObject -Name $oidName -Path $oidContainer -Type 'msPKI-Enterprise-Oid' `
            -OtherAttributes @{
                'msPKI-Cert-Template-OID' = $templateOid
                'msPKI-OID-Attribute'     = 34
                'displayName'             = 'Legacy App Authentication'
            } -Server corp-dc01
    }
    $legacyAttrs['msPKI-Cert-Template-OID'] = $templateOid
    $legacyAttrs['revision']                = 100
    $legacyAttrs['flags']                   = 66104
    New-ADObject -Name $LegacyTemplate -Path $tmplParent -Type 'pKICertificateTemplate' `
        -DisplayName 'Legacy App Authentication' -OtherAttributes $legacyAttrs -Server corp-dc01
} else {
    Set-ADObject -Identity $existing.DistinguishedName -Replace $legacyAttrs -Server corp-dc01
}

# enrolment open to Domain Users, as a self-service legacy template would be
$tmplDn = "CN=$LegacyTemplate,$tmplParent"
$acl = Get-Acl "AD:$tmplDn"
$duSid = (Get-ADGroup 'Domain Users').SID
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $duSid,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55')))
Set-Acl "AD:$tmplDn" -AclObject $acl

& certutil -config "corp-ca01.corp.local\corp-ca01-CA" -SetCAtemplates "+$LegacyTemplate" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "[inject-01] certutil -SetCAtemplates +$LegacyTemplate returned $LASTEXITCODE"
}

# --- verify the inject actually took effect ---
$check = Get-ADUser -Identity $TargetUser -Properties altSecurityIdentities
if (-not ($check.altSecurityIdentities -like 'X509:<RFC822>*')) {
    throw "[inject-01] weak mapping not applied: '$($check.altSecurityIdentities)'"
}
$mode = (Get-ItemProperty -Path $kdc).StrongCertificateBindingEnforcement
if ($mode -ne 1) { throw "[inject-01] StrongCertificateBindingEnforcement is $mode, expected 1" }

Write-Host "[inject-01] $TargetUser is a Domain Admin mapped by X509:<RFC822>$TargetMail"
Write-Host "[inject-01] KDC certificate binding left in Compatibility mode (1)"
