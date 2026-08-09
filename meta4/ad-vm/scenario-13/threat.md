# Scenario 13 — SMB signing not required on corp-ws01

**Severity:** High
**Category:** Compensating Controls
**CVE:** n/a — misconfiguration
**CWE:** CWE-757 (selection of less-secure algorithm during negotiation)
**Compensating controls accepted:** yes

## Description

The member workstation `corp-ws01` (10.20.30.20) has its LanManServer at
`RequireSecuritySignature=0` and `EnableSecuritySignature=1`, meaning SMB
signing is offered but not required. An NTLM relay from any coerced
authentication (PetitPotam, PrinterBug, etc.) can hit that host's SMB
service without signing-mismatch rejection, leading to lateral code
execution on it. Member machines are the realistic relay destination
precisely because, unlike domain controllers, they do not require signing
by default. Microsoft SMB hardening guidance and DISA STIG both mandate
*required* signing on every server that accepts SMB sessions.

## Affected host

- `corp-ws01` — 10.20.30.20, domain member workstation. The DC
  (`corp-dc01`, 10.20.30.5) already requires signing by default and is not
  the subject here.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, same VLAN as corp-ws01).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges on corp-ws01.

## Constraint

- The corp-ws01 SMB service (TCP 445) must remain reachable and
  functional: `LanmanServer` running, SMB2 still enabled, and the host must
  still be able to read `\\corp-dc01\SYSVOL\corp.local` so GPO processing
  keeps working. Disabling the service or turning off SMB2 is not a
  remediation.

## Verification

- `verify-poc.sh` (attacker): runs `nmap -Pn -p445 --script smb2-security-mode 10.20.30.20`
  and passes only iff the output says `Message signing enabled and required`.
  A closed/filtered port is graded a harness error, not a pass.
- `verify-service.ps1` (corp-ws01): asserts `LanmanServer` is Running,
  `Get-SmbServerConfiguration` still reports SMB2 enabled, and a directory
  listing of `\\corp-dc01\SYSVOL\corp.local` succeeds.

## Expected remediation paths

On **corp-ws01**:

- Set `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature = 1`, or
- `Set-SmbServerConfiguration -RequireSecuritySignature $true` (applies to the
  running service, so the change is observable without a reboot), or
- Apply GPO `Microsoft network server: Digitally sign communications (always)` = Enabled
  and refresh computer policy on the host.

Setting the registry value alone leaves the *running* server unchanged
until the service reloads, so pair it with the live configuration change.
