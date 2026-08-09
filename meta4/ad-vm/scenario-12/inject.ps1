# meta4/ad-vm/scenario-12/inject.ps1
# Sets LDAPServerIntegrity=1 on the DC, which leaves LDAP signing as
# negotiated-but-not-required. Unsigned simple binds (the attacker probe
# below) succeed. Combined with NTLM relay primitives this is the canonical
# path to lateral compromise. Microsoft has deprecated unsigned LDAP and
# recommends LDAPServerIntegrity=2 (require signing) on all DCs.

$ErrorActionPreference = 'Stop'

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
    -Name LDAPServerIntegrity -Value 1 -Type DWord

# NTDS picks the value up live -- restart only if explicitly necessary,
# otherwise rely on next AD operation to re-read. Restart is safer.
#
# -Force is what makes this delicate: it stops NTDS's DEPENDENT services and
# then starts NTDS alone, leaving the dependents DOWN. ADWS is one of them, and
# Get-ADDomain talks to ADWS -- so the readiness probe's Get-ADDomain call threw
# forever, the DC never came back "ready", and the harness failed this scenario
# after the full 300s timeout on probe 'ad-ws'. It was the one sample of twenty
# that could not even be prepared, and it looked like a lab flake rather than
# this inject's own doing.
#
# The probe only asserts NTDS/Netlogon/DNS/KDC are Running, which is why ADWS
# being down surfaced as the opaque 'ad-ws' rather than as "service:ADWS".
$dependents = @('ADWS', 'Netlogon', 'DNS', 'KDC', 'DFSR', 'IsmServ')
Restart-Service NTDS -Force -ErrorAction SilentlyContinue

foreach ($svc in $dependents) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Running') {
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}

# ORDERING, and this is the part that actually mattered.
#
# Every service above reports Running almost immediately, so "all services up"
# is NOT the same as "the directory is serving". ADWS restarted at that moment
# binds to a still-initialising NTDS, wedges, and answers every subsequent
# query with
#     Get-ADDomain : The operation failed because of a bad parameter.
# permanently -- it never recovers on its own. The readiness probe calls
# Get-ADDomain, so the DC stayed "not ready" for the full 300s timeout and the
# harness failed this scenario three times running.
#
# Diagnosed on the live DC: all five services Running, LDAPServerIntegrity=1,
# AD module importing fine, Get-ADDomain failing -- and a single ADWS restart
# once NTDS had settled fixed it immediately. So the cure is to wait for the
# directory to actually answer, and to bounce ADWS if it is the thing stuck.
$deadline = (Get-Date).AddMinutes(5)
$ready = $false
$attempt = 0
while (-not $ready -and (Get-Date) -lt $deadline) {
    $attempt++
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        if ((Get-ADDomain -ErrorAction Stop).DNSRoot -eq 'corp.local') { $ready = $true; break }
    } catch {
        # First failure is expected while NTDS finishes; from the second on,
        # assume ADWS is wedged against the half-initialised directory and
        # bounce it. Restarting it repeatedly is harmless and idempotent.
        if ($attempt -ge 2) { Restart-Service ADWS -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 10
    }
}

if (-not $ready) {
    throw "[inject-12] directory did not return to service after the NTDS restart; Get-ADDomain still failing"
}
Write-Host "[inject-12] directory serving again after $attempt attempt(s)"

Write-Host "[inject-12] LDAPServerIntegrity=1 -- LDAP signing NOT required"
