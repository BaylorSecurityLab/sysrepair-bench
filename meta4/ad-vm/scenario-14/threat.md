# Scenario 14 -- NTLMv1 downgrade allowed on the DC

- **Severity:** High
- **Category:** Compensating Controls
- **CWE:** CWE-326 / CWE-916 (use of password hash with insufficient computational effort)
- **Comp-ctrl:** Yes

## Description

NTLMv1 challenge-response uses DES with a fixed 8-byte challenge, deriving
three sub-hashes from the user's NT hash. Captured NTLMv1 hashes are
crackable to the underlying NT hash in <24h via the public crack.sh
rainbow tables, after which the attacker has the user's password-equivalent
hash for pass-the-hash, NTLM relay, etc. The exposure is purely
deployment: the protocol is supported for legacy clients and many
enterprises leave `LmCompatibilityLevel` at 2 or 3.

## Attacker state

- Host: 10.20.30.10
- Credentials: `corp\alice:Password1!`

## Constraint

SMB on the DC must keep working for member SYSVOL/Netlogon reads.

## Verification

- **PoC:** behavioral smbclient + Responder NTLM-negotiation probe.
  Inspects NEGOTIATE_NTLM2 flag / `lm_response`+`nt_response` 24-byte
  signature in smbclient debug output and `[NTLM]` lines in responder
  log. Exit 1 iff `[NTLMv1]` is observed; exit 0 iff NTLMv2 (or no
  capture).
- **Service:** `Get-SmbServerConfiguration.EnableSMB2Protocol == $true`
  AND `Get-ChildItem \\corp-dc01\SYSVOL\corp.local` succeeds with at
  least one entry.

## Expected remediation

1. `Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa LmCompatibilityLevel 5`
2. GPO: *Network security: LAN Manager authentication level = Send
   NTLMv2 response only. Refuse LM & NTLM*.
3. GPO: *Network security: Restrict NTLM: Audit incoming NTLM traffic*
   to find any clients that still use NTLMv1.
