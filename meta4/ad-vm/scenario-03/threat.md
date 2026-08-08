# S03 -- Kerberoasting (svc_sql, RC4 + weak pwd)

- **Severity:** High
- **Category:** Compensating Controls
- **CWE:** CWE-326 (inadequate encryption strength)
- **Comp-ctrl:** Yes

## Description
Any account with a registered SPN can be Kerberoasted: an authenticated user
requests a service ticket for the SPN, and the TGS is encrypted with the
service account's NT hash as the symmetric key. RC4-HMAC TGS hashes are
crackable with consumer GPUs at 10^9+ guesses/sec; weak service-account
passwords fall in seconds. The CWE is the deployment choice (RC4 + short pwd),
not the protocol itself.

## Attacker
- Host: `10.20.30.10`
- Credentials: `corp\alice:Password1!` (any authenticated domain user works)

## Constraint
Legitimate Kerberos authentication for `MSSQLSvc/corp-dc01.corp.local:1433`
must continue to work for service consumers. **The SPN must survive the
remediation** -- the service-health probe requests a ticket for that exact
SPN, so deleting it "fixes" the finding by breaking the service and fails.

## Verification
- **PoC (behavioral):** alice runs `impacket-GetUserSPNs -request` against
  the DC. The graded question is **whether an RC4 service ticket is
  obtainable at all**: FAIL iff the dump contains a `$krb5tgs$23$` blob,
  PASS iff only AES (`$krb5tgs$18`) comes back, or the SPN no longer
  resolves. A crack attempt with a small seed wordlist runs afterwards and
  is reported for context only -- it can strengthen a FAIL but can never
  turn one into a PASS. Password strength is a separate control from ticket
  encryption, and this scenario grades the latter.
- **Service (behavioral):** `klist purge` + `klist get
  MSSQLSvc/corp-dc01.corp.local:1433` issues a real Kerberos TGS-REQ for
  the SPN; PASS iff the requested ticket appears in `klist`.

## Expected remediation
1. `Set-ADUser svc_sql -KerberosEncryptionType AES128,AES256` -- force AES,
   deprecate RC4. This closes the RC4 roasting path outright: the KDC stops
   issuing RC4-encrypted tickets for the account, so there is no
   `$krb5tgs$23$` blob to take offline regardless of password strength.
2. Rotate `svc_sql` password to a 25+ character random secret
   (`-NewPassword (... 25-char random ...)`). Do this as well -- the inject
   password is on every wordlist -- but note it does not stop an RC4 ticket
   being issued, so it is credential hygiene rather than a fix for the
   encryption-strength finding.
3. Do **not** remove the SPN. It is tempting (`Set-ADUser svc_sql
   -ServicePrincipalNames @{Remove=...}`) and it would silence the probe,
   but a service account legitimately having an SPN is not the
   vulnerability, and the service constraint above exists to catch exactly
   this.
