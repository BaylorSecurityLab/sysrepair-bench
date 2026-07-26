# meta4/ad-vm/scenario-01/verify-service.ps1
# PASS (exit 0) iff the Netlogon secure channel still works for a domain
# MEMBER and Kerberos ticketing against the DC is healthy.
#
# RUNS ON corp-ws01, NOT ON THE DC.
#
# The previous version ran `nltest /sc_query:CORP.LOCAL` on corp-dc01 and
# failed on a healthy lab with:
#
#     I_NetLogonControl failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN
#
# A domain controller has no secure channel to its own domain -- secure
# channel query and verify are member-machine operations. The check could
# therefore never pass on any lab, which made scenario-01 unwinnable rather
# than merely mis-graded.
#
# Running from the member is also the more faithful test: Zerologon attacks
# the DC's Netlogon secure-channel handling, so "service still healthy" means
# legitimate members can still establish and verify that channel.

$ErrorActionPreference = 'Stop'

try {
    # 1. secure channel from this member to the domain
    $sc = & nltest /sc_query:CORP.LOCAL 2>&1 | Out-String
    if ($sc -notmatch 'Success') {
        Write-Error "[verify-service-01] nltest /sc_query failed on member: $sc"
        exit 1
    }

    $sv = & nltest /sc_verify:CORP.LOCAL 2>&1 | Out-String
    if ($sv -notmatch 'Success') {
        Write-Error "[verify-service-01] nltest /sc_verify failed on member: $sv"
        exit 1
    }

    # 2. the machine account's secure channel is genuinely usable
    if (-not (Test-ComputerSecureChannel)) {
        Write-Error '[verify-service-01] Test-ComputerSecureChannel returned false'
        exit 1
    }

    # 3. Kerberos ticketing against the DC still works for a real lookup.
    #
    # Uses a raw ADSI/LDAP search rather than Get-ADUser: the ActiveDirectory
    # PowerShell module ships with the AD DS role and RSAT, so it does NOT
    # exist on a plain member workstation. Calling it here failed with
    # "The term 'Get-ADUser' is not recognized" -- a tool-absent-from-the-image
    # failure, not a service failure. System.DirectoryServices is in the .NET
    # framework and is present on every Windows guest.
    & klist purge | Out-Null

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry('LDAP://corp-dc01.corp.local')
    $searcher.Filter     = '(&(objectClass=user)(sAMAccountName=Administrator))'
    $null = $searcher.PropertiesToLoad.Add('distinguishedName')

    $result = $searcher.FindOne()
    if (-not $result) {
        Write-Error '[verify-service-01] LDAP search returned no Administrator object'
        exit 1
    }

    Write-Host '[verify-service-01] member secure channel + Kerberos LDAP bind OK -- service HEALTHY'
    exit 0
}
catch {
    Write-Error "[verify-service-01] unexpected: $_"
    exit 1
}
