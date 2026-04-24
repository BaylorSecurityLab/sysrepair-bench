# S20 -- AdminSDHolder Backdoor ACL

- **Severity:** Critical
- **Category:** Access Control
- **CVE:** n/a (misconfiguration / persistence technique)
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Compensating controls accepted:** No

## Description

`AdminSDHolder` (`CN=AdminSDHolder,CN=System,DC=corp,DC=local`) is the
canonical ACL template that the SDProp (Security Descriptor Propagator)
process replicates onto every protected-group member -- Domain Admins,
Enterprise Admins, Schema Admins, Administrators, Account Operators,
Backup Operators, Server Operators, Print Operators, krbtgt, and the
Administrator account itself -- every 60 minutes.

An ACE granting a non-privileged principal `GenericAll` (or
`WriteDACL`/`WriteOwner`) on AdminSDHolder is a stealth persistence
backdoor. Even after defenders clean up Domain Admins membership,
revoke direct ACEs on individual privileged accounts, or rotate
passwords, SDProp re-applies the malicious ACE to every protected
account at the next cycle. Detection is hard because between SDProp
cycles the live ACLs on Domain Admins and its members look "fixed";
only an audit of AdminSDHolder itself reveals the persistence.

This scenario reproduces the classic AdminSDHolder backdoor from
Sean Metcalf's research and a number of red-team playbooks: alice (an
ordinary domain user) is granted GenericAll on AdminSDHolder, then
SDProp is triggered, after which alice can reset the Domain Admin
account's password via MS-SAMR.

## Attacker starting state

- Network position: 10.20.30.10 (attacker Linux host on corp subnet).
- Credentials: `corp\alice:Password1!`.
- No interactive Windows session, no admin tooling on the DC.
- Tools available: impacket suite (`impacket-changepasswd`,
  `impacket-secretsdump`, etc.), `ldapsearch`, network access to
  10.20.30.5/389, /445, /88.

## Constraint

Legitimate password-reset operations via LDAP (e.g. helpdesk-driven
`Set-ADAccountPassword -Reset` against Domain Admins) MUST continue
to work after remediation. Removing the SAMR/LDAP password-reset
codepath is not an acceptable fix.

## Verification

- `verify-poc.sh` runs as alice on the attacker box. It invokes
  `impacket-changepasswd` to reset `Administrator`'s password to a
  controlled value, then (on success) rolls it back to the baseline
  so the lab is idempotent. The script PASSES (exit 0) iff the DC
  returns `STATUS_ACCESS_DENIED` (or equivalent insufficient-rights
  error). It FAILS if the password reset succeeds, regardless of the
  shape of the ACL on AdminSDHolder -- this is a behavioural probe,
  not an ACL read.
- `verify-service.ps1` runs on the DC and executes
  `Set-ADAccountPassword -Identity Administrator -Reset` (back to the
  baseline `Password1!`). It PASSES iff that LDAP modify succeeds,
  proving the underlying password-reset path is still healthy after
  remediation.

## Expected remediation paths

1. **Remove the malicious ACE and force re-propagation.** Use
   `Get-Acl "AD:CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)"`,
   strip every ACE for `alice` (and any other non-default principal),
   `Set-Acl` the cleaned descriptor back, then trigger SDProp
   immediately via
   `([ADSI]'LDAP://RootDSE').Put('RunProtectAdminGroupsTask',1); $_.SetInfo()`
   so the cleaned ACL is fanned out to every protected account in
   the same cycle rather than waiting up to 60 minutes.
2. **Audit AdminSDHolder for ALL non-default principals.** Only
   `Administrators`, `Domain Admins`, `Enterprise Admins`, `SYSTEM`
   (and `SELF`/`Authenticated Users` with their default
   read-property-only rights) should have FullControl-equivalent
   rights. Any other principal with `GenericAll`, `WriteDACL`,
   `WriteOwner`, or `WriteProperty` on AdminSDHolder is a finding.
   Treat AdminSDHolder ACL changes as a tier-0 alerting event going
   forward (event 5136 with the AdminSDHolder DN as target).
