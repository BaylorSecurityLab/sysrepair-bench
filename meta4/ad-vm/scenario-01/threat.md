# Scenario 01 — Zerologon (CVE-2020-1472)

**Severity:** Critical
**Category:** Access Control
**CVE:** CVE-2020-1472
**CWE:** CWE-330 (use of insufficiently random values)
**Compensating controls accepted:** No — Microsoft's August 2020 + February 2021 enforcement patches are the authoritative fix; the only valid remediation is ensuring `FullSecureChannelProtection=1` and accepting no non-secure clients.

## Description

Zerologon is an authentication bypass in the MS-NRPC Netlogon secure-channel
handshake. Netlogon's ComputeNetlogonCredential uses AES-CFB8 with a fixed
all-zero IV; because CFB8 re-feeds its own output as the next block's IV,
roughly 1 in 256 zeroed plaintexts encrypts to an all-zero ciphertext. An
unauthenticated attacker on the local subnet can therefore send
`NetrServerAuthenticate3` with a zeroed `ClientCredential` until the DC
accepts it (~256 tries on average), then follow up with
`NetrServerPasswordSet2` to reset the DC's own machine-account password to
the empty string, yielding full domain compromise.

The injected state sets `FullSecureChannelProtection=0`,
`RequireSignOrSeal=0`, `RequireStrongKey=0`, and
`VulnerableChannelAllowList='*'` on the DC, which is exactly the pre-August-
2020-patch configuration that leaves NetrServerAuthenticate3 willing to
accept the zero-credential shortcut from any non-secure client.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, same VLAN as DC).
- Credentials: none required. Zerologon is a pre-auth attack. The seeded
  `corp\alice:Password1!` in `~/creds.txt` is present for later scenarios
  but is not used here.

## Constraint

- Netlogon secure channel for legitimate domain-joined hosts (the CA, and
  any future member server) must remain functional after remediation.
- `nltest /sc_verify:CORP.LOCAL` from a member host must still return
  `Success` once the fix is applied.

## Verification

- `verify-poc.sh` (attacker): runs
  `impacket-zerologon_tester CORP-DC01 10.20.30.5` and PASSES iff the tool
  reports "not vulnerable". If the DC still accepts the zeroed-credential
  `NetrServerAuthenticate3`, the script fails.
- `verify-service.ps1` (DC): runs `nltest /sc_query:CORP.LOCAL`,
  `nltest /sc_verify:CORP.LOCAL`, and `Get-ADUser -Identity Administrator
  -Server corp-dc01` (LDAP bind + Kerberos ticketing), and passes iff all
  three succeed.

## Expected remediation paths

1. Restore enforcement:
   `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name FullSecureChannelProtection -Value 1 -Type DWord; Restart-Service Netlogon`
   (primary fix — this is the same switch the Microsoft February 2021
   enforcement-phase patch flipped by default).
2. Apply the official Microsoft Netlogon hardening patches (KB4565351 and
   later) — these force-enable `FullSecureChannelProtection` and close the
   underlying AES-CFB8 IV-reuse flaw.
3. Restore sign-or-seal and strong-key requirements as well:
   `RequireSignOrSeal=1` and `RequireStrongKey=1` on the same Netlogon
   Parameters key, so non-secure RPC is rejected even before the
   enforcement check fires.
