# Scenario 07 - ADCS ESC1 (ENROLLEE_SUPPLIES_SUBJECT)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC1 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

Certificate template `ESC1-SmartCard` is published on the Enterprise CA with
`msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT (1)`, a Client
Authentication EKU (`1.3.6.1.5.5.7.3.2`), and enrollment open to
`Domain Users`. Any low-privileged domain user can request a certificate
with `subjectAltName=upn=administrator@corp.local`, then PKINIT-authenticate
as that user via Schannel/Kerberos, recovering the target's NT hash via the
UnPAC-the-Hash technique. This is the canonical SpecterOps ESC1 path and
yields an immediate domain-admin compromise from any standard user account.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, routes to CA + DC).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges anywhere; alice is a member of `Domain Users` only.

## Constraint

- Legitimate User certificate enrollment must continue to work. The
  service-health probe enrolls a real certificate against the built-in
  `User` template via `certreq -submit` against
  `corp-ca01.corp.local\corp-ca01-CA` and asserts a `.cer` is issued.
  Remediations that block the User template, stop CertSvc, or unpublish
  the CA are NOT acceptable.

## Verification

- `verify-poc.sh` (attacker): runs `certipy-ad req` from alice's creds to
  enroll in `ESC1-SmartCard` with
  `-upn administrator@corp.local`, then `certipy-ad auth -pfx administrator.pfx`.
  Exits 1 (PoC works) iff the auth output contains `NT hash` or
  `AS-REP received`. Exits 0 (BLOCKED) iff the request is denied
  (`access_denied`, `template not found`, `enrollment denied`, `cannot enroll`)
  or no PFX is produced.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real cert
  against the built-in `User` template with `certreq -submit` and asserts
  a non-trivial `.cer` is issued.

## Expected remediation paths

1. Clear the dangerous flag:
   `Set-ADObject "CN=ESC1-SmartCard,CN=Certificate Templates,CN=Public Key Services,CN=Services,<configNC>" -Replace @{ 'msPKI-Certificate-Name-Flag' = 0 }`
   - Removes ENROLLEE_SUPPLIES_SUBJECT so the CA builds the subject from AD,
     not from attacker input.
2. Remove `Domain Users` from the template's enrollment ACL via `dsacls`
   or `Set-Acl` on `AD:CN=ESC1-SmartCard,...` (revoke the Certificate-Enrollment
   extended right `0e10c968-78fb-11d2-90d4-00c04f79dc55`).
3. Unpublish the template from the CA:
   `certutil -SetCAtemplates -ESC1-SmartCard` (template stays in AD schema
   but is no longer offered for enrollment by the CA).
