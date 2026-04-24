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
     `certipy-ad auth -pfx administrator.pfx`. Exits 1 (PoC works) iff the
     auth output contains `NT hash` or `AS-REP received`. Exits 0 (BLOCKED)
     iff the on-behalf-of issuance is denied
     (`access_denied`, `enrollment denied`, `invalid signature`) or no
     Administrator PFX is produced.
- `verify-service.ps1` (CA): runs `certutil -ping` then enrolls a real cert
  against the built-in `User` template with `certreq -submit` and asserts
  a non-trivial `.cer` is issued.

## Expected remediation paths

1. Restrict the Enrollment Agent template's enrollment ACL to only authorized
   PKI admin groups (not `Domain Users`):
   `Set-Acl AD:CN=ESC3-Agent,...` to revoke the Certificate-Enrollment
   extended right (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) for the
   `Domain Users` SID. Without enrol on `ESC3-Agent`, alice cannot mint
   the agent cert in step 1.
2. Disable enroll-on-behalf-of on the user template by clearing
   `msPKI-RA-Application-Policies` and setting `msPKI-RA-Signature = 0` on
   `ESC3-User`:
   `Set-ADObject "CN=ESC3-User,..." -Clear msPKI-RA-Application-Policies -Replace @{ 'msPKI-RA-Signature' = 0 }`
   - Removes the RA-signature requirement so step 2 of the chain is
     structurally impossible.
3. Configure CA-side Enrollment Agent restrictions to whitelist only specific
   agents and target templates:
   `certutil -setreg policy\EnrollmentAgentRights <SDDL>` then
   `Restart-Service CertSvc`. The SDDL grants the Enrollment Agent right only
   to a named PKI-admin SID against a named target template, preventing
   alice (even if she has an agent cert) from invoking on-behalf-of against
   `ESC3-User`.
