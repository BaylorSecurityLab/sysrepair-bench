# meta4/ad-vm/scenario-09/inject.ps1
# Creates the ESC3 chain: ESC3-Agent (Certificate Request Agent EKU, enrollable
# by Domain Users) + ESC3-User (Client-Auth, requires RA signature from a
# Cert-Request-Agent). Together these enable the Enrollment-Agent
# on-behalf-of attack: alice enrolls in the agent template, then uses the
# agent cert to request a Client-Auth cert on behalf of Administrator.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# Reusable inline helper - registers a certificate template in AD schema and
# publishes it on the issuing CA, then grants enrollment to the named groups.
function Publish-LabTemplate {
    param(
        [string]$TemplateName,        # e.g., "ESC3-Agent"
        [string]$DisplayName,         # e.g., "Lab ESC3 Agent"
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

# ESC3-Agent: the dangerous-EKU template alice can enrol in.
$agentAttrs = @{
    'msPKI-Certificate-Name-Flag'   = 0x80000000     # SUBJECT_REQUIRE_DIRECTORY_PATH (default-ish)
    'msPKI-Enrollment-Flag'         = 0
    'msPKI-Private-Key-Flag'        = 0x10           # 16 = ATTEST_NONE
    'msPKI-Template-Minor-Revision' = 1
    'msPKI-Template-Schema-Version' = 2
    'pKIExtendedKeyUsage'           = @('1.3.6.1.4.1.311.20.2.1')   # Certificate Request Agent EKU
    'msPKI-Certificate-Application-Policy' = @('1.3.6.1.4.1.311.20.2.1')
    'pKIKeyUsage'                   = [byte[]](0xa0)
    'msPKI-RA-Signature'            = 0
    'msPKI-Minimal-Key-Size'        = 2048
    'pKIDefaultKeySpec'             = 1
    'pKIMaxIssuingDepth'            = 0
    'pKIExpirationPeriod'           = [byte[]](0,0x40,0x39,0x87,0x2e,0xe1,0xfe,0xff)
    'pKIOverlapPeriod'              = [byte[]](0,0x80,0xa6,0x0a,0xff,0xde,0xff,0xff)
}
Publish-LabTemplate -TemplateName 'ESC3-Agent' -DisplayName 'Lab ESC3 Agent' `
    -Attrs $agentAttrs -EnrollGroups @('Domain Users')

# ESC3-User: the impersonatable target, enrollable on-behalf-of via an RA signature.
$userAttrs = @{
    'msPKI-Certificate-Name-Flag'   = 0x80000000
    'msPKI-Enrollment-Flag'         = 0
    'msPKI-Private-Key-Flag'        = 0
    'msPKI-Template-Minor-Revision' = 1
    'msPKI-Template-Schema-Version' = 2
    'pKIExtendedKeyUsage'           = @('1.3.6.1.5.5.7.3.2')   # Client Authentication
    'msPKI-Certificate-Application-Policy' = @('1.3.6.1.5.5.7.3.2')
    'msPKI-RA-Application-Policies' = @('1.3.6.1.4.1.311.20.2.1')   # require Cert-Request-Agent
    'pKIKeyUsage'                   = [byte[]](0xa0)
    'msPKI-RA-Signature'            = 1                        # require 1 RA signature
    'msPKI-Minimal-Key-Size'        = 2048
    'pKIDefaultKeySpec'             = 1
    'pKIMaxIssuingDepth'            = 0
    'pKIExpirationPeriod'           = [byte[]](0,0x40,0x39,0x87,0x2e,0xe1,0xfe,0xff)
    'pKIOverlapPeriod'              = [byte[]](0,0x80,0xa6,0x0a,0xff,0xde,0xff,0xff)
}
Publish-LabTemplate -TemplateName 'ESC3-User' -DisplayName 'Lab ESC3 User' `
    -Attrs $userAttrs -EnrollGroups @('Domain Users')

Write-Host "[inject-09] ESC3-Agent + ESC3-User published (Enrollment Agent on-behalf-of attack open)"
