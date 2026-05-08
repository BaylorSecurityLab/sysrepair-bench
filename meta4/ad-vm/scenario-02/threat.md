# Scenario 02 — MachineAccountQuota foothold (NoPac chain)

**Severity:** Critical
**Category:** Access Control
**CVE:** CVE-2021-42278 / CVE-2021-42287 (NoPac chain; this scenario hardens the foothold step)
**CWE:** CWE-269 (improper privilege management)
**Compensating controls accepted:** No

## Description

`ms-DS-MachineAccountQuota=10` is Microsoft's longstanding Windows default.
Any authenticated domain user can create up to 10 computer accounts, which
the NoPac chain renames to a DC's hostname before requesting a service
ticket as DA. The CVEs themselves are patched in the base box; the
residual misconfig is MAQ. Microsoft's hardening guidance recommends
MAQ=0 in environments where users don't legitimately self-enroll
machines.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet).
- Credentials: domain user `corp\alice:Password1!`.
- No admin privileges on DC.

## Constraint

- Domain-joined computer reads must still work for legitimate DAs.
- `Get-ADComputer corp-ca01 -Server corp-dc01` from a member must still
  succeed after remediation.

## Verification

- `verify-poc.sh` (attacker): runs `impacket-addcomputer` as alice
  against `corp-dc01.corp.local`, exits 0 iff the create is denied.
- `verify-service.ps1` (DC): runs `Get-ADComputer corp-ca01 -Server corp-dc01`
  and `Get-ADComputer corp-dc01`, exits 0 iff both objects are readable
  and the CA computer object is `Enabled`.

## Expected remediation paths

1. `Set-ADDomain -Identity corp.local -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }` (primary).
2. Apply the NoPac patches (KB5008602, KB5008603) — already present in the base box.
3. Remove `Authenticated Users` from `Add Computers to the Domain` rights.
