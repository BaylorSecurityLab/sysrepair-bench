# Scenario 10 - ADCS ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC6 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

The CA-wide flag `EDITF_ATTRIBUTESUBJECTALTNAME2` makes the CA honor
user-supplied subjectAltName attributes on ANY template. Even a tightly-scoped
template like the built-in `User` becomes a privilege escalation primitive:
alice requests a User cert but supplies `-upn administrator@corp.local`, and
the CA writes that UPN into the issued cert's SAN. PKINIT then authenticates
alice as Administrator, and UnPAC-the-Hash recovers Administrator's NT hash.

Microsoft explicitly documents this as a misconfiguration; the flag exists for
legacy compatibility (Windows 2000-era enrollment quirks) and should not be set
on production CAs. Setting it converts every template enrollable by Domain
Users into an ESC1-equivalent escalation path, regardless of the template's
own `ENROLLEE_SUPPLIES_SUBJECT` flag, because the override happens at the CA
policy module rather than at the template.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, routes to CA + DC).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges anywhere; alice is a member of `Domain Users` only.

## Constraint

- Legitimate User certificate enrollment without a SAN override must continue
  to work. The service-health probe enrolls a real certificate against the
  built-in `User` template via `certreq -submit` against
  `corp-ca01.corp.local\corp-ca01-CA` and asserts a `.cer` is issued.
  Remediations that block the User template, stop CertSvc, or unpublish the CA
  are NOT acceptable. Note: clearing the EDITF flag rejects only the SAN
  override, not legitimate template enrollment.

## Verification

- `verify-poc.sh` (attacker): alice runs `certipy-ad req -template User
  -upn administrator@corp.local` against `corp-ca01-CA`. With EDITF set, the
  CA honors the SAN override and issues a cert with Administrator's UPN.
  Then `certipy-ad auth -pfx administrator.pfx` performs PKINIT and recovers
  Administrator's NT hash. Exits 1 (PoC works) iff the auth output contains
  `NT hash` or `AS-REP received`. Exits 0 (BLOCKED) iff the request is denied
  (`access_denied`, `enrollment denied`, `invalid request`, `denied by
  policy`) or no Administrator PFX is produced.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real cert
  against the built-in `User` template with `certreq -submit` and asserts
  a non-trivial `.cer` is issued.

## Expected remediation paths

1. Clear the EDITF flag and restart the CA service (primary fix):
   `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 ;
   Restart-Service CertSvc`.
   The CA policy module stops honoring user-supplied SAN attributes; the
   built-in `User` template still enrolls normally because the User template
   itself does not set `ENROLLEE_SUPPLIES_SUBJECT`.
2. Audit existing certs for unexpected SAN entries (UPN values that do not
   match the issuing identity) using `Get-CertificationAuthority` /
   `certutil -view` and revoke any cert whose SAN UPN does not match the
   requester. Combine with (1) to close the window opened by exploitation
   that may have already occurred.
