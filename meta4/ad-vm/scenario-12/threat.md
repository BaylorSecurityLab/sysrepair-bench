# S12 - LDAP signing not required (NTLM relay surface)

- **Severity:** High
- **Category:** Compensating Controls
- **CVE:** n/a
- **CWE:** CWE-287 / CWE-300
- **Comp-ctrl:** Yes

## Description
When LDAP signing is not required (`LDAPServerIntegrity=1`), the DC accepts
unsigned simple binds and unsigned SASL binds. NTLM blobs captured via
PetitPotam, PrinterBug, or LLMNR poisoning can be replayed straight to the
DC's LDAP listener with no integrity check. Combined with `ldap-relay-scan`,
attackers add their own user to a privileged group or write
`msDS-AllowedToActOnBehalfOfOtherIdentity` for resource-based constrained
delegation takeover.

## Attacker state
- Source: 10.20.30.10 (attacker host)
- Credential: `corp\alice:Password1!`

## Constraint
Legitimate signed LDAP binds must keep working (the verify-service
`Get-ADUser` call uses Negotiate signing).

## Verification
- Behavioral: `ldapsearch -x` simple bind from the attacker host must be
  rejected with `strongAuthRequired`.
- Behavioral: `Get-ADUser -Identity Administrator -Server corp-dc01` must
  still succeed (signed bind path).

## Expected remediation
1. `Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters LDAPServerIntegrity 2`
2. Domain Controllers GPO: `Domain controller: LDAP server signing requirements = Require signing`
3. Audit `LDAP signing` events (Event ID 2887/2889) for unsigned-bind
   clients before flipping the require flag.
