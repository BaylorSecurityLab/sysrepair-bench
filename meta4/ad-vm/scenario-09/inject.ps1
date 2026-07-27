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

    # Test-ADObject DOES NOT EXIST -- the ActiveDirectory module ships only
    # Get-/New-/Set-/Remove-ADObject. This threw CommandNotFoundException on
    # every run, so neither ESC3 template was created or published and the
    # scenario was never actually set up. A -Filter search is used because
    # -Identity throws when the object is absent, which is the normal case on a
    # clean baseline.
    $tmplParent = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    $existing = Get-ADObject -SearchBase $tmplParent -Filter "name -eq '$TemplateName'" `
                             -Server corp-dc01 -ErrorAction SilentlyContinue
    # A SCHEMA-VERSION-2 TEMPLATE NEEDS AN OID, A revision AND flags.
    #
    # Without msPKI-Cert-Template-OID the CA cannot resolve the request -- it
    # maps V2 templates by OID, not by name -- so enrollment returns
    # 0x80094800 CERTSRV_E_UNSUPPORTED_CERT_TYPE even though
    # `certutil -SetCAtemplates` reports the template "Already present", and
    # `certutil -CATemplates` fails with E_UNEXPECTED. Confirmed against the
    # built-in User template, which carries all three where ours had none.
    # ESC3 needs BOTH of its templates well-formed, so this runs per template.
    if (-not $existing) {
        $oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
        $forestArc = (Get-ADObject -Identity $oidContainer -Properties 'msPKI-Cert-Template-OID' `
                                   -Server corp-dc01).'msPKI-Cert-Template-OID'
        if (-not $forestArc) { throw "[inject] cannot read the forest template OID arc from $oidContainer" }

        $templateOid = '{0}.{1}.{2}' -f $forestArc, (Get-Random -Minimum 1000000 -Maximum 99999999),
                                                    (Get-Random -Minimum 1000000 -Maximum 99999999)

        $oidName = "$TemplateName-OID"
        if (-not (Get-ADObject -SearchBase $oidContainer -Filter "name -eq '$oidName'" `
                               -Server corp-dc01 -ErrorAction SilentlyContinue)) {
            New-ADObject -Name $oidName -Path $oidContainer -Type 'msPKI-Enterprise-Oid' `
                -OtherAttributes @{
                    'msPKI-Cert-Template-OID' = $templateOid
                    'msPKI-OID-Attribute'     = 34
                    'displayName'             = $DisplayName
                } -Server corp-dc01
        }

        $Attrs = $Attrs.Clone()
        $Attrs['msPKI-Cert-Template-OID'] = $templateOid
        $Attrs['revision']                = 100
        $Attrs['flags']                   = 66104

        New-ADObject -Name $TemplateName -Path $tmplParent `
            -Type 'pKICertificateTemplate' -DisplayName $DisplayName -OtherAttributes $Attrs -Server corp-dc01
    } else {
        Set-ADObject -Identity $tmplPath -Replace $Attrs -Server corp-dc01
    }

    # Publish on the issuing CA. certutil's exit code is checked -- this was
    # piped to Out-Null with no check, so a failure here was invisible.
    & certutil -SetCAtemplates +$TemplateName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "[inject] certutil -SetCAtemplates +$TemplateName returned $LASTEXITCODE"
    }

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
