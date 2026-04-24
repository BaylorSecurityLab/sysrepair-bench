# meta4/ad-vm/scenario-07/inject.ps1
# Creates the ESC1-SmartCard template: Client-Auth EKU + ENROLLEE_SUPPLIES_SUBJECT
# flag + enrollment open to Domain Users.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# Reusable inline helper - registers a certificate template in AD schema and
# publishes it on the issuing CA, then grants enrollment to the named groups.
function Publish-LabTemplate {
    param(
        [string]$TemplateName,        # e.g., "ESC1-SmartCard"
        [string]$DisplayName,         # e.g., "Lab ESC1 Smart Card"
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

# ESC1 schema attributes.
$attrs = @{
    'msPKI-Certificate-Name-Flag'   = 1                          # ENROLLEE_SUPPLIES_SUBJECT
    'msPKI-Enrollment-Flag'         = 0
    'msPKI-Private-Key-Flag'        = 0
    'msPKI-Template-Minor-Revision' = 1
    'msPKI-Template-Schema-Version' = 2
    'pKIExtendedKeyUsage'           = @('1.3.6.1.5.5.7.3.2')     # Client Authentication
    'pKIKeyUsage'                   = [byte[]](0x86)              # digitalSignature+keyEncipherment
    'msPKI-RA-Signature'            = 0
    'msPKI-Minimal-Key-Size'        = 2048
    'pKIDefaultKeySpec'             = 1
    'pKIMaxIssuingDepth'            = 0
    'pKIExpirationPeriod'           = [byte[]](0,0x40,0x39,0x87,0x2e,0xe1,0xfe,0xff)
    'pKIOverlapPeriod'              = [byte[]](0,0x80,0xa6,0x0a,0xff,0xde,0xff,0xff)
}
Publish-LabTemplate -TemplateName 'ESC1-SmartCard' -DisplayName 'Lab ESC1 Smart Card' `
    -Attrs $attrs -EnrollGroups @('Domain Users')

Write-Host "[inject-07] ESC1-SmartCard template published with ENROLLEE_SUPPLIES_SUBJECT"
