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

    # Test-ADObject DOES NOT EXIST. The ActiveDirectory module ships Get-, New-,
    # Set- and Remove-ADObject and nothing else, so this line threw
    # CommandNotFoundException on every run and the template was never created
    # or published. Gates could not have been measuring this scenario at all.
    #
    # A -Filter search is used rather than Get-ADObject -Identity because
    # -Identity raises ADIdentityNotFoundException when the object is absent,
    # which is the normal case on a clean baseline; a filter simply returns
    # nothing.
    $tmplParent = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    $existing = Get-ADObject -SearchBase $tmplParent -Filter "name -eq '$TemplateName'" `
                             -Server corp-dc01 -ErrorAction SilentlyContinue

    # A SCHEMA-VERSION-2 TEMPLATE NEEDS AN OID, A revision AND flags.
    #
    # Without msPKI-Cert-Template-OID the CA cannot resolve the request -- it
    # maps V2 templates by OID, not by name -- and every enrollment came back
    #   0x80094800 CERTSRV_E_UNSUPPORTED_CERT_TYPE
    # even though `certutil -SetCAtemplates` reported the template "Already
    # present". `certutil -CATemplates` also failed with E_UNEXPECTED
    # ("Unexpected method call sequence"), which is what a malformed template
    # object in the CA's list looks like.
    #
    # Confirmed by comparing against the built-in User template in this forest:
    # it carries an OID, revision and flags, while ours had all three empty.
    #
    # The OID must live under the forest's own arc, published on the OID
    # container (CN=OID,CN=Public Key Services,...). Built-in User is
    # <arc>.1.1, so appending two components is the established shape.
    if (-not $existing) {
        $oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
        $forestArc = (Get-ADObject -Identity $oidContainer -Properties 'msPKI-Cert-Template-OID' `
                                   -Server corp-dc01).'msPKI-Cert-Template-OID'
        if (-not $forestArc) { throw "[inject] cannot read the forest template OID arc from $oidContainer" }

        $templateOid = '{0}.{1}.{2}' -f $forestArc, (Get-Random -Minimum 1000000 -Maximum 99999999),
                                                    (Get-Random -Minimum 1000000 -Maximum 99999999)

        # Companion msPKI-Enterprise-Oid object. The CA resolves from the
        # template attribute, but the MMC and some tooling expect this to exist,
        # and leaving a dangling OID makes the PKI view look corrupt.
        $oidName = "$TemplateName-OID"
        if (-not (Get-ADObject -SearchBase $oidContainer -Filter "name -eq '$oidName'" `
                               -Server corp-dc01 -ErrorAction SilentlyContinue)) {
            New-ADObject -Name $oidName -Path $oidContainer -Type 'msPKI-Enterprise-Oid' `
                -OtherAttributes @{
                    'msPKI-Cert-Template-OID' = $templateOid
                    'msPKI-OID-Attribute'     = 34          # template OID
                    'displayName'             = $DisplayName
                } -Server corp-dc01
        }

        $Attrs = $Attrs.Clone()
        $Attrs['msPKI-Cert-Template-OID'] = $templateOid
        $Attrs['revision']                = 100
        $Attrs['flags']                   = 66104           # V2, published to AD

        New-ADObject -Name $TemplateName -Path $tmplParent `
            -Type 'pKICertificateTemplate' -DisplayName $DisplayName -OtherAttributes $Attrs -Server corp-dc01
    } else {
        Set-ADObject -Identity $tmplPath -Replace $Attrs -Server corp-dc01
    }

    # Publish on the issuing CA so it is offered to enrollees. certutil's exit
    # code is checked: this used to be piped to Out-Null with no check, so a
    # failure here was invisible.
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
