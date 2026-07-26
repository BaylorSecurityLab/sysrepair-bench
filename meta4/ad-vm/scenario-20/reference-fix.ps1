# meta4/ad-vm/scenario-20/reference-fix.ps1
# Reference remediation for an AdminSDHolder backdoor ACL.
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# AdminSDHolder is the ACL template SDProp stamps onto every protected group
# and member (Domain Admins, Administrator, krbtgt, ...) roughly hourly. A
# GenericAll ACE for a normal user there is a persistence backdoor: even if
# you clean up the protected objects, SDProp puts the rights back.
#
# Remediation is two steps and BOTH are required:
#   1. remove the ACE from AdminSDHolder, so it stops being re-stamped
#   2. run SDProp immediately, so already-stamped objects are cleaned now
#      rather than up to an hour later
#
# Doing only (1) leaves alice with GenericAll on the protected objects until
# the next SDProp cycle -- still exploitable, and a partial fix should not pass.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domainDN   = (Get-ADDomain).DistinguishedName
$adminSDDN  = "CN=AdminSDHolder,CN=System,$domainDN"
$alice      = Get-ADUser alice
$aliceSid   = [System.Security.Principal.SecurityIdentifier]$alice.SID

$acl = Get-Acl "AD:$adminSDDN"
$removed = 0
foreach ($rule in @($acl.Access)) {
    $sid = if ($rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
               $rule.IdentityReference
           } else {
               try { ([System.Security.Principal.NTAccount]$rule.IdentityReference).Translate([System.Security.Principal.SecurityIdentifier]) }
               catch { $null }
           }
    if ($sid -eq $aliceSid) {
        $null = $acl.RemoveAccessRule($rule)
        $removed++
    }
}

if ($removed -gt 0) {
    Set-Acl "AD:$adminSDDN" -AclObject $acl
    Write-Host "[fix-20] removed $removed ACE(s) for alice from AdminSDHolder"
} else {
    Write-Host '[fix-20] no ACEs for alice on AdminSDHolder -- already clean'
}

# Run SDProp now so protected objects are re-stamped from the cleaned template
# immediately instead of at the next cycle.
$root = [ADSI]'LDAP://RootDSE'
$root.Put('RunProtectAdminGroupsTask', 1)
$root.SetInfo()
Write-Host '[fix-20] SDProp triggered'

Start-Sleep -Seconds 20

$after = (Get-Acl "AD:$adminSDDN").Access | Where-Object {
    $sid = if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) { $_.IdentityReference }
           else { try { ([System.Security.Principal.NTAccount]$_.IdentityReference).Translate([System.Security.Principal.SecurityIdentifier]) } catch { $null } }
    $sid -eq $aliceSid
}
if ($after) { throw '[fix-20] alice still has ACEs on AdminSDHolder' }

Write-Host '[fix-20] COMPLETE'
