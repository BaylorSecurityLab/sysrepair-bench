# meta4/ad-vm/scenario-08/reference-fix.ps1
# Reference remediation for ADCS ESC2.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# ESC2 is a template carrying the Any Purpose EKU (or no EKU at all) that
# ordinary users can enroll in. Any Purpose means the issued certificate is
# valid for client authentication among everything else, so it is ESC1 by
# another route.
#
# Same remediation shape as scenario-07: unpublish from the CA, then strip the
# over-broad enroll grant so republishing cannot silently restore it.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$template = 'ESC2-AnyPurpose'

& certutil -SetCAtemplates "-$template" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "[fix-08] certutil -SetCAtemplates returned $LASTEXITCODE"
}

$configNC = (Get-ADRootDSE).configurationNamingContext
$tmplPath = "CN=$template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

if (Get-ADObject -Identity $tmplPath -ErrorAction SilentlyContinue) {
    $acl = Get-Acl "AD:$tmplPath"
    $enrollGuids = @(
        [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55',
        [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
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
        Write-Host "[fix-08] removed $removed broad enroll ACE(s) from $template"
    }
}

$published = (& certutil -CATemplates 2>&1 | Out-String)
if ($published -match [regex]::Escape($template)) {
    throw "[fix-08] $template is still published on the CA"
}

# The CA must still be SERVING. Unpublishing a template must not take it
# offline. Observed on scenario-07 against the live lab: certipy failed with
# ept_s_not_registered for 91AE6020-9E3C-11CF-8D7C-00AA00C091BE
# (ICertRequestD, the CA's RPC enrollment interface). A remediation that stops
# the service "fixes" the finding by breaking what it protects, and the PoC
# then reports an inconclusive connection error rather than a denial.
$deadline = (Get-Date).AddSeconds(120)
$serving = $false
while ((Get-Date) -lt $deadline) {
    if ((Get-Service CertSvc -ErrorAction SilentlyContinue).Status -eq 'Running') {
        certutil -ping 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $serving = $true; break }
    }
    Start-Sleep -Seconds 5
}
if (-not $serving) {
    Write-Host '[fix-08] CA not answering; restarting CertSvc'
    Restart-Service CertSvc -Force -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(180)
    while ((Get-Date) -lt $deadline) {
        if ((Get-Service CertSvc -ErrorAction SilentlyContinue).Status -eq 'Running') {
            certutil -ping 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $serving = $true; break }
        }
        Start-Sleep -Seconds 5
    }
}
if (-not $serving) {
    throw '[fix-08] CertSvc is not answering certutil -ping. The CA is down, which is not a remediation.'
}

Write-Host "[fix-08] $template unpublished; CA still serving"
Write-Host '[fix-08] COMPLETE'
