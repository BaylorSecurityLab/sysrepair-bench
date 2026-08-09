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
less-useful certificate -- narrower EKU, or a subject built from alice's own
directory identity rather than the requested UPN -- is not accepted: the
template is still published, still enrollable by any domain user, and one
attribute change away from being exploitable again. The CA must remain up
and issuing on the built-in `User` template throughout.

## Expected remediation paths

1. **Stop the CA offering the template at all.** Unpublish
   `ESC2-AnyPurpose` from the issuing CA (`certutil -SetCAtemplates
   -ESC2-AnyPurpose`, or via the Certification Authority console's
   Certificate Templates node). The template object stays in the AD
   configuration partition, but the CA no longer accepts requests for it and
   answers `CERTSRV_E_UNSUPPORTED_CERT_TYPE`. This is the remediation the
   finding is graded against. Confirm afterwards that the CA is still
   serving -- `certutil -ping` must succeed and `User` enrollment must still
   work. Taking CertSvc down is never an acceptable fix.
2. Alongside (1), remove the over-broad enrollment grant so republishing the
   template cannot silently restore the hole: revoke the
   Certificate-Enrollment extended right
   (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) and Certificate-AutoEnrollment
   (`a05b8cc2-17bc-4802-a710-e7c15ab866a2`) from `Domain Users` /
   `Authenticated Users` on `AD:CN=ESC2-AnyPurpose,...`, via `dsacls` or
   `Set-Acl`.
3. If the template genuinely has to be kept, the attribute-level hardening
   is to give it a real Client Authentication EKU instead of Any Purpose
   (`pKIExtendedKeyUsage` and `msPKI-Certificate-Application-Policy` set to
   `1.3.6.1.5.5.7.3.2`) and to clear `ENROLLEE_SUPPLIES_SUBJECT` from
   `msPKI-Certificate-Name-Flag`. Both are correct hardening, and both leave
   the template published and enrollable by `Domain Users`, so neither meets
   the acceptance criterion on its own. Pair them with (1) and (2) rather
   than substituting for them.
