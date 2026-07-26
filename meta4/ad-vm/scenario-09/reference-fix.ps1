# meta4/ad-vm/scenario-09/reference-fix.ps1
# Reference remediation for ADCS ESC3 (Enrollment Agent on-behalf-of).
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# ESC3 is a two-template attack: an enrollment-agent template any user can
# enroll in, plus a target template that accepts an RA signature from such an
# agent. Holding the agent certificate lets the attacker request a certificate
# ON BEHALF OF anyone, including Administrator.
#
# Both templates must be unpublished -- removing only one leaves the chain
# broken but the other half still enrollable, and a partial fix should not
# pass.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$templates = @('ESC3-Agent', 'ESC3-User')
$configNC  = (Get-ADRootDSE).configurationNamingContext
$enrollGuids = @(
    [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55',
    [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
)
$broad = @('Domain Users', 'Authenticated Users', 'Everyone')

foreach ($template in $templates) {
    & certutil -SetCAtemplates "-$template" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "[fix-09] certutil -SetCAtemplates -$template returned $LASTEXITCODE"
    }

    $tmplPath = "CN=$template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    if (-not (Get-ADObject -Identity $tmplPath -ErrorAction SilentlyContinue)) { continue }

    $acl = Get-Acl "AD:$tmplPath"
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
        Write-Host "[fix-09] removed $removed broad enroll ACE(s) from $template"
    }
}

$published = (& certutil -CATemplates 2>&1 | Out-String)
foreach ($template in $templates) {
    if ($published -match [regex]::Escape($template)) {
        throw "[fix-09] $template is still published on the CA"
    }
}

Write-Host "[fix-09] $($templates -join ' and ') unpublished from the CA"
Write-Host '[fix-09] COMPLETE'
