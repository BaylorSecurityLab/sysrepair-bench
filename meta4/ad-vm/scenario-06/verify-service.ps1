# meta4/ad-vm/scenario-06/verify-service.ps1
# PASS (exit 0) iff the DRS replication interface actually answers -- the
# protocol DCSync abuses. If it serves legitimate callers, the service is
# healthy regardless of the ACL under test.
#
# The previous version ran `repadmin /showrepl /csv` and required the output to
# contain 'CN=Schema' or 'CN=Configuration'. On a healthy lab it failed with
# "repadmin output missing expected NC references".
#
# Cause: /showrepl reports inbound replication PARTNERS. corp.local is a
# SINGLE-DC forest, so it has none and the CSV is essentially empty. The check
# silently assumed a multi-DC topology, so it could never pass here -- making
# scenario-06 unwinnable rather than merely mis-graded.
#
# /showobjmeta queries replication metadata for a specific object over the same
# DRS interface and works on a single DC, so it tests what actually matters.

$ErrorActionPreference = 'Stop'

try {
    $dn = (Get-ADDomain -ErrorAction Stop).DistinguishedName

    # DRS metadata query for the domain root -- exercises the replication
    # interface itself rather than the partner list.
    $meta = & repadmin /showobjmeta corp-dc01 "$dn" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "repadmin /showobjmeta exit=$LASTEXITCODE output=$meta"
    }
    if ($meta -notmatch 'Loc\.USN|Originating') {
        throw "repadmin /showobjmeta returned no replication metadata: $meta"
    }

    # The naming contexts DCSync targets must be present and enumerable.
    $ncs = (Get-ADRootDSE -ErrorAction Stop).namingContexts
    foreach ($needle in 'CN=Schema', 'CN=Configuration') {
        if (-not ($ncs -match [regex]::Escape($needle))) {
            throw "naming context '$needle' absent from RootDSE"
        }
    }

    # DRS is answering and the directory is serving reads.
    $null = Get-ADUser -Identity Administrator -Server corp-dc01 -ErrorAction Stop

    Write-Host '[verify-service-06] DRS metadata + naming contexts OK -- service HEALTHY'
    exit 0
}
catch {
    Write-Error "[verify-service-06] $_"
    exit 1
}
