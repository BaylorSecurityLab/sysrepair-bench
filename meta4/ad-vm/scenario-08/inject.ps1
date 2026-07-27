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

    # Test-ADObject DOES NOT EXIST -- the ActiveDirectory module ships only
    # Get-/New-/Set-/Remove-ADObject. This threw CommandNotFoundException on
    # every run, so the template was never created or published and the
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
    # NO pKIExtendedKeyUsage KEY AT ALL. "No EKU" means the attribute is
    # ABSENT, not present-and-empty: passing @() made New-ADObject reject the
    # whole call with "Cannot validate argument on parameter 'OtherAttributes'.
    # The argument collection is empty", so the ESC2 template was never created.
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
