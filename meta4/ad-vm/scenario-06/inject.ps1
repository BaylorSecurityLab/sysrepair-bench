# meta4/ad-vm/scenario-06/inject.ps1
# Grants alice DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
# extended rights on the domain head, which is the exact ACE shape DCSync
# needs to dump krbtgt hashes via the DRS protocol.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domainDN = (Get-ADDomain).DistinguishedName
$alice    = Get-ADUser alice
$acl      = Get-Acl "AD:$domainDN"

$ridReplGet    = New-Object Guid('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')
$ridReplGetAll = New-Object Guid('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')

foreach ($rid in @($ridReplGet, $ridReplGetAll)) {
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        [System.Security.Principal.SecurityIdentifier]$alice.SID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $rid
    )
    $acl.AddAccessRule($ace)
}
Set-Acl "AD:$domainDN" -AclObject $acl
Write-Host "[inject-06] alice granted DS-Replication-Get-Changes[-All] on domain root"
