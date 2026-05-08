# Scenario 04 -- AS-REP Roasting (dave: DONT_REQ_PREAUTH + weak pwd)

- **Severity:** High
- **Category:** Compensating Controls
- **CVE:** n/a
- **CWE:** CWE-287 (Improper Authentication) / CWE-326 (Inadequate Encryption Strength)
- **Compensating control:** Yes

## Description

The Active Directory user-account-control flag `UF_DONT_REQUIRE_PREAUTH`
(surfaced in PowerShell as `DoesNotRequirePreAuth=True`) disables Kerberos
pre-authentication for the account. With pre-auth disabled the KDC will
respond to an unauthenticated AS-REQ with an AS-REP whose enc-part is
encrypted under the user's long-term key (RC4-HMAC by default). An
attacker on the network can request that AS-REP without any credentials,
take it offline, and brute-force the user's password against a wordlist.
When the account also has a weak/dictionary password (here `Winter24`,
6 letters + 2 digits, top of every seasonal list), the crack is
sub-second on commodity hardware.

## Attacker state

- Network position: 10.20.30.10 (attacker VM), no AD credentials.
- Tooling: `impacket-GetNPUsers` to dump AS-REPs, `hashcat -m 18200` to
  crack them.
- AS-REP roasting is fully pre-auth: no creds, no SMB session, no LDAP
  bind required -- only routable access to TCP/UDP 88 on the DC.

## Constraint

Legitimate password-based Kerberos authentication for `dave` must keep
working. The remediation must rely on re-enabling pre-auth and rotating
the password, not on disabling/locking the account.

## Verification

- **PoC (behavioral):** attacker runs `impacket-GetNPUsers corp.local/
  -usersfile users.txt -dc-ip 10.20.30.5 -no-pass`. If dave still has
  `DONT_REQ_PREAUTH`, an AS-REP `$krb5asrep$23$...` blob is returned
  and `hashcat -m 18200` recovers the cleartext within 30s against a
  6-entry seasonal wordlist. Exit 1 only on full cleartext recovery;
  exit 0 covers both "pre-auth required, AS-REP refused" and "AS-REP
  dumped but password uncrackable" PASS paths.
- **Service (behavioral):** DC runs `Get-ADUser -Identity dave
  -Credential corp\dave -Server corp-dc01`. The cmdlet performs an
  LDAP bind that internally drives the full KRB5 AS-REQ /
  pre-auth-data / TGS-REQ chain, so a successful bind proves the
  Kerberos pre-auth path is healthy end-to-end.

## Remediation (canonical)

1. Re-enable pre-auth on dave:
   `Set-ADAccountControl -Identity dave -DoesNotRequirePreAuth $false`
2. Rotate dave to a 25+ character random password (out-of-band crack
   resistance; AS-REP roast is harmless against entropy this high
   anyway, but the inject password is on every wordlist so it must
   change too):
   `Set-ADAccountPassword -Identity dave -Reset
    -NewPassword (ConvertTo-SecureString '<25+ char rand>' -AsPlainText -Force)`
3. Audit the rest of the directory for the same misconfiguration:
   `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth`
   and clear the flag on every hit unless there is an explicit,
   documented reason (almost always there is none).

## Why "Compensating Controls"

There is nothing to patch here -- AS-REP roasting is a feature of the
Kerberos protocol exposed by an account-level UAC bit. The remediation
is configuration and credential hygiene, not a vendor fix. This is the
defining shape of the Compensating Controls category.
