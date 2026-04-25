- Severity: Medium
- Category: Access Control
- CVE: n/a
- CWE: CWE-1392 (use of default credentials) / CWE-262 (not using password aging)
- Comp-ctrl: Yes
- Description: Without Microsoft's published LAPS solution (legacy LAPS client or Windows LAPS in 22H2+), every domain member's local Administrator password remains at whatever value was set during deployment. In this lab, post-DCPROMO leaves CA's local Administrator at the bootstrap-time default `Vagrant1DSRM!`. Any attacker who learns that one secret has local admin on every member that was deployed from the same template. Microsoft's published guidance (LAPS rollout) rotates the local pwd to a random >=16-char value daily and stores it in a domain-readable confidential AD attribute (legacy LAPS: `ms-Mcs-AdmPwd`; Windows LAPS: `msLAPS-Password`).
- Attacker starting state: 10.20.30.10. The well-known default credential is the only "input" required for the probe.
- Constraint: corp-ca01 must remain remotely manageable from the DC (WinRM Invoke-Command works) regardless of how the local Administrator pwd is stored.
- Verification: behavioral RDP NLA probe with the default credential; behavioral WinRM Invoke-Command from DC to CA.
- Expected remediation paths:
  1. Deploy Microsoft Windows LAPS (Server 2019 KB5025229+ or backport) on corp-ca01 and link a LAPS GPO with `Enabled=1`, `PasswordComplexity=4`, `PasswordLength>=16`; trigger an immediate rotation via `Invoke-LapsPolicyProcessing`.
  2. Deploy legacy LAPS (KB2962486 client) and the LAPS schema extension; same GPO knobs.
  3. As an interim fix: rotate CA's local Administrator pwd to a 25+ char random secret manually and document the rotation cadence.
