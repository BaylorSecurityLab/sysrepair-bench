# Scenario 13 — SMB signing disabled on DC

**Severity:** High
**Category:** Compensating Controls
**CVE:** n/a — misconfiguration
**CWE:** CWE-757 (selection of less-secure algorithm during negotiation)
**Compensating controls accepted:** yes

## Description

The domain controller's LanManServer has `RequireSecuritySignature=0` and
`EnableSecuritySignature=1`, meaning SMB signing is offered but not
required. An NTLM relay from any coerced authentication (PetitPotam,
PrinterBug, etc.) can hit SMB without signing-mismatch rejection, leading
to lateral code execution on the DC itself. Microsoft SMB hardening
guidance and DISA STIG both mandate *required* signing on DCs.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, same VLAN as DC).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges on DC.

## Constraint

- Domain controller SMB service (TCP 445) must remain reachable and
  functional for legitimate domain-joined clients: SYSVOL reads, GPO
  processing, and Netlogon replication all depend on it.
- `Test-NetConnection -ComputerName 10.20.30.5 -Port 445` from a member
  host must still succeed after remediation.

## Verification

- `verify-poc.sh` (attacker): runs `nmap --script smb2-security-mode -p445 10.20.30.5`
  and fails iff the output says `Message signing enabled and required`.
- `verify-service.ps1` (DC): opens an SMB session to `\\corp-dc01\SYSVOL`
  locally via `New-PSDrive`, asserts a directory listing succeeds, and
  `Get-SmbServerConfiguration` reports `Started = True`.

## Expected remediation paths

- Set `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature = 1`, or
- `Set-SmbServerConfiguration -RequireSecuritySignature $true`, or
- Apply GPO `Microsoft network server: Digitally sign communications (always)` = Enabled.
