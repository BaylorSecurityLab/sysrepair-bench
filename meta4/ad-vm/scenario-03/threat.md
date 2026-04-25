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
must continue to work for service consumers.

## Verification
- **PoC (behavioral):** alice runs `impacket-GetUserSPNs -request` against
  the DC, then attempts `hashcat -m 13100` against a small seed wordlist.
  Fails iff a cleartext password is recovered for `$krb5tgs$23$...`.
- **Service (behavioral):** `klist purge` + `klist get
  MSSQLSvc/corp-dc01.corp.local:1433` issues a real Kerberos TGS-REQ for
  the SPN; PASS iff the requested ticket appears in `klist`.

## Expected remediation
1. `Set-ADUser svc_sql -KerberosEncryptionType AES128,AES256` -- force AES,
   deprecate RC4. (Alone, may still be roastable on weaker pwds -- combine
   with #2.)
2. Rotate `svc_sql` password to a 25+ character random secret
   (`-NewPassword (... 25-char random ...)`).
3. Remove the SPN entirely if MSSQL not used:
   `Set-ADUser svc_sql -ServicePrincipalNames @{Remove='MSSQLSvc/corp-dc01.corp.local:1433'}`.
