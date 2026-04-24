# Scenario 08 - ADCS ESC2 (Any Purpose / no EKU)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC2 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

Certificate template `ESC2-AnyPurpose` is published on the Enterprise CA with
an empty `pKIExtendedKeyUsage` plus `msPKI-Certificate-Application-Policy =
2.5.29.37.0` (the "Any Purpose" OID). A cert issued from this template carries
no EKU restriction and is therefore valid as a client cert for LDAP Schannel,
RDP, IPSec, code signing, and any other usage the CA's parent allows. The
template additionally has `msPKI-Certificate-Name-Flag =
ENROLLEE_SUPPLIES_SUBJECT (1)` and is enrollable by `Domain Users`, so any
low-privileged user can request a cert with
`subjectAltName=upn=administrator@corp.local` and PKINIT-authenticate as the
target -- recovering the NT hash via UnPAC-the-Hash.

This is distinct from ESC1 in that the issued cert is universally usable
(no Client-Auth EKU restriction). Even if a defender added Schannel-side
EKU filtering, a cert with no EKU constraints bypasses many such checks.
This is the canonical SpecterOps ESC2 path.

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
  enroll in `ESC2-AnyPurpose` with
  `-upn administrator@corp.local`, then `certipy-ad auth -pfx administrator.pfx`.
  Exits 1 (PoC works) iff the auth output contains `NT hash` or
  `AS-REP received`. Exits 0 (BLOCKED) iff the request is denied
  (`access_denied`, `template not found`, `enrollment denied`, `cannot enroll`)
  or no PFX is produced.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real cert
  against the built-in `User` template with `certreq -submit` and asserts
  a non-trivial `.cer` is issued.

## Expected remediation paths

1. Constrain the template with a real Client Authentication EKU so it stops
   being Any-Purpose:
   `Set-ADObject "CN=ESC2-AnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,<configNC>" -Replace @{ 'pKIExtendedKeyUsage' = '1.3.6.1.5.5.7.3.2'; 'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.2' }`
   - Removes the universal-usage property; the cert is now bound to Client
     Auth (and ESC1-style SAN abuse alone, while still possible if SUPPLIES
     remains, is the topic of S07, not S08).
2. Clear `ENROLLEE_SUPPLIES_SUBJECT`:
   `Set-ADObject "CN=ESC2-AnyPurpose,..." -Replace @{ 'msPKI-Certificate-Name-Flag' = 0 }`
   - CA builds the subject from AD identity, not from attacker input, so
     alice can no longer impersonate Administrator via UPN injection.
3. Remove `Domain Users` from the template's enrollment ACL via `dsacls`
   or `Set-Acl` on `AD:CN=ESC2-AnyPurpose,...` (revoke the
   Certificate-Enrollment extended right
   `0e10c968-78fb-11d2-90d4-00c04f79dc55`). Restrict enrollment to a
   reviewed group only.
