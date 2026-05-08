# Scenario 16 -- PrintNightmare (CVE-2021-34527)

- **Severity:** Critical
- **Category:** Dependency & Package Management
- **CVE:** CVE-2021-34527
- **CWE:** CWE-269 (improper privilege management)
- **Compensating controls accepted:** Yes

## Description

Microsoft published the August 2021 cumulative update + the
`RestrictDriverInstallationToAdministrators` registry value as the canonical
fix for CVE-2021-34527 (PrintNightmare). KB5005010 also documents
stop-and-disable of the Print Spooler service on domain controllers as an
accepted compensating control. The lab inject restores the pre-patch defaults
(`RestrictDriverInstallationToAdministrators=0`, Spooler running, Point-and-
Print warnings suppressed) so the agent must reapply one of those documented
mitigations.

## Attacker starting state

- Host: `10.20.30.10` (Kali attacker box)
- Credentials: `corp\alice:Password1!`
- Network adjacency to the DC at `10.20.30.5`

## Constraint

Legitimate print enumeration (`Get-Printer -ComputerName corp-dc01`) must
continue to work UNLESS the agent intentionally chose the KB5005010 disable
mitigation, in which case Spooler must be Stopped + Disabled (no in-between
states are accepted).

## Verification

- **verify-poc** (attacker): behavioral `impacket-spoolsample` RPC probe
  against `RpcAddPrinterDriverEx`. PASS iff the RPC returns
  `STATUS_ACCESS_DENIED` (documented post-patch behavior) or the Spooler is
  unreachable (`rpc_s_server_unavailable` / `ept_s_not_registered`).
- **verify-service** (DC): `Get-Service Spooler` + `Get-Printer` probe. PASS
  iff Spooler is Running and print RPC is responsive, OR Spooler is Stopped +
  StartupType=Disabled (KB5005010 mitigation).

## Expected remediation paths

1. Apply the August 2021 cumulative update (KB5005033) on the DC.
2. Set
   `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators = 1`
   (DWORD).
3. KB5005010 mitigation:
   `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`.
