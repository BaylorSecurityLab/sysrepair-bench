# meta4/ad-vm/scenario-07/reference-fix.ps1
# Reference remediation for ADCS ESC1.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# ESC1 is a template that (a) permits the enrollee to supply the subject
# alternative name, (b) has a client-authentication EKU, and (c) is enrollable
# by ordinary users. Together those let any authenticated user request a
# certificate naming Administrator and then authenticate as them.
#
# Remediation: unpublish the template from the CA so it can no longer be
# requested, and remove the over-broad enroll grant so republishing it does not
# silently restore the hole. Unpublishing alone is the operative fix -- the CA
# refuses requests for templates it does not offer -- but leaving the ACL in
# place would be a latent landmine.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$template = 'ESC1-SmartCard'

# 1. Unpublish from the CA. This is what stops enrollment immediately.
& certutil -SetCAtemplates "-$template" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "[fix-07] certutil -SetCAtemplates returned $LASTEXITCODE"
}

# 2. Remove the broad enroll grant from the template object.
$configNC  = (Get-ADRootDSE).configurationNamingContext
$tmplPath  = "CN=$template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

if (Get-ADObject -Identity $tmplPath -ErrorAction SilentlyContinue) {
    $acl = Get-Acl "AD:$tmplPath"
    $enrollGuids = @(
        [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55',  # Certificate-Enrollment
        [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'   # Certificate-AutoEnrollment
    )
    $broad = @('Domain Users', 'Authenticated Users', 'Everyone')

    $removed = 0
    foreach ($rule in @($acl.Access)) {
        $name = $rule.IdentityReference.Value
        if (($broad | Where-Object { $name -like "*$_" }) -and
            $rule.ActiveDirectoryRights -match 'ExtendedRight' -and
            $enrollGuids -contains $rule.ObjectType) {
            $null = $acl.RemoveAccessRule($rule)
            $removed++
        }
    }
    if ($removed -gt 0) {
        Set-Acl "AD:$tmplPath" -AclObject $acl
        Write-Host "[fix-07] removed $removed broad enroll ACE(s) from $template"
    }
}

# 3. Verify the CA no longer offers it.
$published = (& certutil -CATemplates 2>&1 | Out-String)
if ($published -match [regex]::Escape($template)) {
    throw "[fix-07] $template is still published on the CA"
}

Write-Host "[fix-07] $template unpublished from the CA"
Write-Host '[fix-07] COMPLETE'
