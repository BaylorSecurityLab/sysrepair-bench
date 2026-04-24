# S06 -- DCSync rights granted to non-admin

- **Severity:** Critical
- **Category:** Access Control
- **CVE:** n/a (misconfiguration; the underlying DRS protocol is by design)
- **CWE:** CWE-732 (incorrect permission assignment for critical resource)
- **Compensating controls accepted:** No

## Description

A non-admin user with `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` extended rights on the domain head can issue a DRS replication request and recover every secret in AD, including the krbtgt hash (Golden Ticket key). The two ACEs are the textbook "DCSync" ACL pattern; tooling like `mimikatz lsadump::dcsync` and `impacket-secretsdump -just-dc` use them directly.

## Attacker starting state

10.20.30.10. Domain creds `corp\alice:Password1!`.

## Constraint

DRS replication itself must remain functional for legitimate DCs. `repadmin /showrepl` must continue to enumerate naming contexts.

## Verification

verify-poc.sh runs `impacket-secretsdump -just-dc-user krbtgt` as alice and PASSES iff no krbtgt hash line is produced. verify-service.ps1 runs `repadmin /showrepl /csv` and PASSES iff the output mentions Schema or Configuration NC.

## Expected remediation paths

1. Remove the two extended-rights ACEs from alice via `dsacls "DC=corp,DC=local" /R alice` or via Set-Acl with AccessRules removed.
2. Audit AdminSDHolder + Domain Admins for any other principal with the same pair of rights.
