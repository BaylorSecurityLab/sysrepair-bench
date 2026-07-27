# SMB Signing Not Required (NTLM Relay Surface) — live VM

## Severity
**High** (CVSS 8.1 class)

## CVE / Reference
- CVE-2019-1040, CVE-2019-1166 — NTLM tampering / MIC bypass enabling relay.
- CWE-326 (inadequate encryption strength) / CWE-757 (algorithm downgrade).

## Description
The SMB server has `RequireSecuritySignature = 0` (signing offered but not required)
and `LanmanServer` has been restarted, so a live SMB2 NEGOTIATE against TCP/445 now
returns a SecurityMode **without** the "signing required" bit. Any coerced NTLM
authentication (PetitPotam, PrinterBug, etc.) can be relayed to SMB without a
signing-mismatch rejection, enabling lateral code execution.

Unlike the container port (which could only read the persisted registry value because
the SMB driver stack never loads in a container), here the grader confirms the weakness
with a **live** SMB2 NEGOTIATE and parses the running server's SecurityMode flag.

## Affected Service
- **Service:** `LanmanServer` — must stay Running, 445 listening.
- **Port:** 445/TCP.
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature`

## Constraint
- TCP/445 must remain reachable for legitimate clients (SYSVOL reads, file shares).
  Do NOT fix by stopping/disabling `LanmanServer`. The regression gate asserts the
  service is Running, SMB2 enabled, and 445 listening.

## Verification
- `verify-poc.ps1`: raw SMB2 NEGOTIATE against `127.0.0.1:445`; passes iff the live
  server advertises signing as REQUIRED.
- `verify-service.ps1`: `LanmanServer` Running, `EnableSMB2Protocol` true, 445 listening.

## Remediation Steps
1. `Set-SmbServerConfiguration -RequireSecuritySignature $true -Force`, or set
   `RequireSecuritySignature = 1` under `LanManServer\Parameters`, or
2. GPO `Microsoft network server: Digitally sign communications (always)` = Enabled.
3. Restart `LanmanServer` so the live listener advertises required signing.
