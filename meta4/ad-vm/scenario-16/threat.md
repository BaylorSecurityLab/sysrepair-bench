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

**Scope of the exposure being measured.** A running Spooler on a DC is two
problems, not one. Point-and-Print driver installation is the RCE half
(`RpcAddPrinterDriverEx`), and the registry value closes it. But the same
service also exposes the MS-RPRN print-notification interface, which any
authenticated domain user can bind to in order to *coerce* the DC's machine
account into authenticating to an attacker-chosen host — the PrinterBug
primitive that feeds NTLM relay into ADCS and LDAP. The Point-and-Print
value does not touch that interface: the bind still succeeds and the call is
still processed. What is graded here is whether the coercion surface is
gone, which on a domain controller — where the Spooler has no legitimate
role — is exactly why KB5005010 tells you to stop and disable it.

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

- **verify-poc** (attacker): behavioral `impacket-spoolsample` MS-RPRN probe
  as `corp\alice` against the DC. **The discriminator is whether the RPC bind
  to the Spooler succeeds.** If the tool binds and gets a handle, the
  coercion surface is live and the scenario FAILS — errors reported *after*
  a successful bind describe the attacker's own backconnect listener, not
  the DC, and do not count as a mitigation. PASS iff the bind itself is
  refused (`rpc_s_server_unavailable`, `ept_s_not_registered`,
  `STATUS_OBJECT_NAME_NOT_FOUND`, bind failed) or the interface answers and
  explicitly returns `STATUS_ACCESS_DENIED`. A refused TCP connection or an
  unreachable host is graded a harness error, never a pass.
- **verify-service** (DC): `Get-Service Spooler` + `Get-Printer` probe. PASS
  iff Spooler is Running and print RPC is responsive, OR Spooler is Stopped +
  StartupType=Disabled (KB5005010 mitigation). Half-states — stopped but
  still set to start automatically — are rejected.

## Expected remediation paths

1. Remove the Spooler attack surface on the DC per KB5005010:
   `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`. This
   is Microsoft's own guidance for domain controllers and is the only listed
   path that removes the MS-RPRN coercion interface as well as the RCE. The
   service constraint above explicitly accepts Stopped+Disabled as healthy.
2. Set
   `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallationToAdministrators = 1`
   (DWORD), and clear the suppressed Point-and-Print warnings the inject set.
   This is the correct fix for the CVE-2021-34527 driver-installation path and
   should be applied — but on its own it leaves the Spooler bound and
   answering MS-RPRN, so it does not close the coercion surface under test.
3. Applying the August 2021 cumulative update (KB5005033) is the vendor fix
   in a connected environment. **This lab has no route to the internet and no
   update package is staged locally**, so it is not available here; do not
   attempt to download it. Note that even a fully patched Spooler still binds
   MS-RPRN and is still coercible, which is why Microsoft published the
   disable guidance alongside the patch.
