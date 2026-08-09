# Scenario 09 - ADCS ESC3 (Enrollment Agent on-behalf-of)

**Severity:** High
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC3 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

ESC3 chains two certificate templates to escalate from any low-privileged
domain user to Administrator. The first template, `ESC3-Agent`, carries the
Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`) and is enrollable by
`Domain Users`. The second template, `ESC3-User`, issues Client-Authentication
certificates and requires an RA signature from a holder of the
Certificate-Request-Agent EKU (`msPKI-RA-Application-Policies`).

Attack chain: alice enrolls in `ESC3-Agent` and obtains an agent cert. She then
uses that cert to sign a `request on behalf of CORP\Administrator` against
`ESC3-User`. The CA accepts the agent's RA signature and issues a Client-Auth
PFX in Administrator's name. PKINIT-authenticating with the resulting PFX
recovers Administrator's NT hash via UnPAC-the-Hash. End result: full domain
compromise from any standard user account.

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

- `verify-poc.sh` (attacker): two-step certipy-ad chain.
  1. `certipy-ad req -template 'ESC3-Agent'` from alice's creds to obtain
     an agent PFX. If alice cannot enrol in the agent template, the chain
     is already broken (BLOCKED, exit 0).
  2. `certipy-ad req -template 'ESC3-User' -on-behalf-of 'CORP\Administrator'
     -pfx alice.pfx` to coerce an Administrator PFX, then
     `certipy-ad auth -pfx administrator.pfx`. Exits 1 (PoC works) iff a PFX
     naming `administrator` is issued at all -- recovering the NT hash is
     corroboration, not the threshold. Exits 0 (BLOCKED) **only** on an
     explicit denial (`access_denied`, `enrollment denied`, `invalid
     signature`).
- **Holding the agent certificate is itself the finding.** If step 1 still
  succeeds, alice is one call away from impersonation and the chain counts
  as present: an unexplained failure at step 2 with an agent cert already in
  hand is graded FAIL, not blocked.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real cert
  against the built-in `User` template with `certreq -submit` and asserts
  a non-trivial `.cer` is issued.

## Acceptance criterion

The finding is closed only when the CA **refuses the request outright** and
says so -- ideally at step 1, so alice never obtains an enrollment-agent
certificate in the first place. The recognised denial is the CA declining to
serve the template: `CERTSRV_E_UNSUPPORTED_CERT_TYPE` / `0x80094800` / "not
supported by this CA", template not found, access denied, or enrollment
denied. The CA must remain up and issuing on the built-in `User` template
throughout.

## Expected remediation paths

1. **Stop the CA offering both halves of the chain.** Unpublish
   `ESC3-Agent` *and* `ESC3-User` from the issuing CA (`certutil
   -SetCAtemplates -ESC3-Agent`, likewise for `ESC3-User`, or via the
   Certification Authority console). Removing only one leaves the other
   still enrollable by any domain user, and a partial fix should not pass.
   This is the remediation the finding is graded against. Confirm afterwards
   that the CA is still serving -- `certutil -ping` must succeed and `User`
   enrollment must still work. Taking CertSvc down is never an acceptable
   fix.
2. Alongside (1), strip the over-broad enrollment grant from both template
   objects so republishing cannot silently restore the chain: revoke the
   Certificate-Enrollment extended right
   (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) and Certificate-AutoEnrollment
   (`a05b8cc2-17bc-4802-a710-e7c15ab866a2`) from `Domain Users` /
   `Authenticated Users` on `AD:CN=ESC3-Agent,...` and
   `AD:CN=ESC3-User,...`.
3. Attribute- and CA-level hardening is the right shape for templates you
   intend to keep: clearing `msPKI-RA-Application-Policies` and setting
   `msPKI-RA-Signature = 0` on `ESC3-User` removes the on-behalf-of
   requirement, and `certutil -setreg policy\EnrollmentAgentRights <SDDL>`
   plus a CertSvc restart restricts the Enrollment Agent right to named
   principals and target templates. Both are worth doing -- but each leaves
   `ESC3-Agent` published and enrollable, so the agent certificate is still
   mintable and the acceptance criterion is not met. Pair them with (1) and
   (2) rather than substituting for them.
