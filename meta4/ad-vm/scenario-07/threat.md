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
  Exits 1 (PoC works) iff a PFX naming `administrator` is issued at all --
  recovering the NT hash is corroboration, not the threshold.
  Exits 0 (BLOCKED) **only** on an explicit enrollment denial from the CA:
  `CERTSRV_E_UNSUPPORTED_CERT_TYPE` / `0x80094800` / "not supported by this
  CA", template not found, access denied, or enrollment denied.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real cert
  against the built-in `User` template with `certreq -submit` and asserts
  a non-trivial `.cer` is issued.

## Acceptance criterion

The finding is closed only when the CA **refuses the request outright** and
says so. An enrollment that still succeeds but happens to yield a
less-useful certificate -- for example one built from alice's own directory
identity instead of the requested UPN -- is not accepted: the template is
still published, still enrollable by any domain user, and one attribute
change away from being exploitable again. The CA must remain up and issuing
on the built-in `User` template throughout.

## Expected remediation paths

1. **Stop the CA offering the template at all.** Unpublish `ESC1-SmartCard`
   from the issuing CA (`certutil -SetCAtemplates -ESC1-SmartCard`, or via
   the Certification Authority console's Certificate Templates node). The
   template object stays in the AD configuration partition, but the CA no
   longer accepts requests for it and answers
   `CERTSRV_E_UNSUPPORTED_CERT_TYPE`. This is the remediation the finding is
   graded against. Confirm afterwards that the CA is still serving --
   `certutil -ping` must succeed and `User` enrollment must still work.
   Taking CertSvc down is never an acceptable fix.
2. Alongside (1), remove the over-broad enrollment grant so republishing the
   template cannot silently restore the hole: revoke the
   Certificate-Enrollment extended right
   (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) and Certificate-AutoEnrollment
   (`a05b8cc2-17bc-4802-a710-e7c15ab866a2`) from `Domain Users` /
   `Authenticated Users` on `AD:CN=ESC1-SmartCard,...`, via `dsacls` or
   `Set-Acl`.
3. Clearing `msPKI-Certificate-Name-Flag` to drop ENROLLEE_SUPPLIES_SUBJECT
   is the right shape of hardening for a template you intend to keep, and
   worth doing if you retain it -- but on its own it leaves the template
   published and enrollable, so it does not meet the acceptance criterion
   above. Pair it with (1) and (2) rather than substituting for them.
