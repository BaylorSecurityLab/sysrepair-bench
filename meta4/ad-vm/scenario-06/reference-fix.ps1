# meta4/ad-vm/scenario-06/reference-fix.ps1
# Reference remediation for DCSync rights granted to a non-admin.
#
# This is a NEGATIVE-CONTROL FIXTURE, not part of the scenario an agent sees.
# It exists so the four proof gates can be evaluated:
#
#   gate 2 (still solvable)  applying this must make BOTH gates pass. If a
#                            stronger check breaks this fix, the fix was
#                            wrong -- never weaken the check to accommodate it.
#   gate 3 (sabotage)        re-running inject.ps1 on top of this must make the
#                            PoC fail again.
#
# Without it, a passing dual gate is not evidence: it cannot be distinguished
# from a check that passes because nothing was tested.
#
# The remediation is the exact inverse of inject.ps1: remove alice's
# DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended
# rights from the domain head. Those two ACEs together are what DCSync needs
# to pull secrets over the DRS protocol.
#
# Deliberately narrow: it removes only the two replication ACEs for this one
# principal, rather than resetting the domain ACL wholesale. A blunt reset
# would also mask the vulnerability while changing far more than the scenario
# is about, and would make gate 3 meaningless.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domainDN = (Get-ADDomain).DistinguishedName
$alice    = Get-ADUser alice
$aliceSid = [System.Security.Principal.SecurityIdentifier]$alice.SID

$ridReplGet    = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes
$ridReplGetAll = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
$targets = @($ridReplGet, $ridReplGetAll)

$acl = Get-Acl "AD:$domainDN"

$removed = 0
foreach ($rule in @($acl.Access)) {
    if ($rule.IdentityReference -isnot [System.Security.Principal.SecurityIdentifier]) {
        try { $ruleSid = ([System.Security.Principal.NTAccount]$rule.IdentityReference).Translate([System.Security.Principal.SecurityIdentifier]) }
        catch { continue }
    } else {
        $ruleSid = $rule.IdentityReference
    }

    if ($ruleSid -ne $aliceSid) { continue }
    if ($rule.ActiveDirectoryRights -notmatch 'ExtendedRight') { continue }
    if ($targets -notcontains $rule.ObjectType) { continue }

    $null = $acl.RemoveAccessRule($rule)
    $removed++
}

if ($removed -eq 0) {
    Write-Host '[fix-06] no DCSync ACEs found for alice -- already remediated'
} else {
    Set-Acl "AD:$domainDN" -AclObject $acl
    Write-Host "[fix-06] removed $removed DCSync ACE(s) for alice from the domain head"
}

# Verify the rights are genuinely gone rather than trusting the write.
$after = (Get-Acl "AD:$domainDN").Access | Where-Object {
    $sid = if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) { $_.IdentityReference }
           else { try { ([System.Security.Principal.NTAccount]$_.IdentityReference).Translate([System.Security.Principal.SecurityIdentifier]) } catch { $null } }
    $sid -eq $aliceSid -and $_.ActiveDirectoryRights -match 'ExtendedRight' -and $targets -contains $_.ObjectType
}
if ($after) { throw "[fix-06] DCSync ACEs still present for alice after removal" }

Write-Host '[fix-06] COMPLETE'
