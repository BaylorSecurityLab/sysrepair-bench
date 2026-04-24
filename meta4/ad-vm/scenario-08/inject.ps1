# meta4/ad-vm/scenario-08/inject.ps1
# Creates the ESC2-AnyPurpose template: NO EKU + Any-Purpose application
# policy + ENROLLEE_SUPPLIES_SUBJECT + enrollment open to Domain Users.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# Reusable inline helper - registers a certificate template in AD schema and
# publishes it on the issuing CA, then grants enrollment to the named groups.
function Publish-LabTemplate {
    param(
        [string]$TemplateName,        # e.g., "ESC2-AnyPurpose"
        [string]$DisplayName,         # e.g., "Lab ESC2 Any Purpose"
        [hashtable]$Attrs,            # schema attributes hashtable
        [string[]]$EnrollGroups       # e.g., @("Domain Users")
    )
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $tmplPath = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    if (-not (Test-ADObject -Identity $tmplPath -ErrorAction SilentlyContinue)) {
        New-ADObject -Name $TemplateName -Path "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC" `
            -Type 'pKICertificateTemplate' -DisplayName $DisplayName -OtherAttributes $Attrs -Server corp-dc01
    } else {
        Set-ADObject -Identity $tmplPath -Replace $Attrs -Server corp-dc01
    }

    # Publish on issuing CA so it's offered to enrollees.
    certutil -SetCAtemplates +$TemplateName | Out-Null

    # Grant enrollment ACL.
    $acl = Get-Acl "AD:$tmplPath"
    foreach ($grp in $EnrollGroups) {
        $sid = (Get-ADGroup -Identity $grp).SID
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            [System.Security.Principal.SecurityIdentifier]$sid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'  # Certificate-Enrollment right
        )
        $acl.AddAccessRule($ace)
    }
    Set-Acl "AD:$tmplPath" -AclObject $acl
}

# ESC2 schema attributes: empty pKIExtendedKeyUsage + Any-Purpose application
# policy OID (2.5.29.37.0) means the issued cert is valid for ANY usage --
# Schannel client auth, RDP, IPSec, code signing, etc. Combined with
# ENROLLEE_SUPPLIES_SUBJECT, alice can stamp Administrator's UPN into the cert.
$attrs = @{
    'msPKI-Certificate-Name-Flag'   = 1                          # ENROLLEE_SUPPLIES_SUBJECT
    'msPKI-Enrollment-Flag'         = 0
    'msPKI-Private-Key-Flag'        = 0
    'msPKI-Template-Minor-Revision' = 1
    'msPKI-Template-Schema-Version' = 2
    'pKIExtendedKeyUsage'           = @()                        # NO EKU == Any Purpose
    'msPKI-Certificate-Application-Policy' = @('2.5.29.37.0')    # Any Purpose OID
    'pKIKeyUsage'                   = [byte[]](0x86)
    'msPKI-RA-Signature'            = 0
    'msPKI-Minimal-Key-Size'        = 2048
    'pKIDefaultKeySpec'             = 1
    'pKIMaxIssuingDepth'            = 0
    'pKIExpirationPeriod'           = [byte[]](0,0x40,0x39,0x87,0x2e,0xe1,0xfe,0xff)
    'pKIOverlapPeriod'              = [byte[]](0,0x80,0xa6,0x0a,0xff,0xde,0xff,0xff)
}
Publish-LabTemplate -TemplateName 'ESC2-AnyPurpose' -DisplayName 'Lab ESC2 Any Purpose' `
    -Attrs $attrs -EnrollGroups @('Domain Users')

Write-Host "[inject-08] ESC2-AnyPurpose template published with no EKU + ENROLLEE_SUPPLIES_SUBJECT"
