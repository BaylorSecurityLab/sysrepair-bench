- Severity: High
- Category: Access Control
- CVE: n/a (CVE-2014-1812 is the original; remediation is MS14-025 / KB2962486)
- CWE: CWE-256 (plaintext storage of password) / CWE-321 (use of hard-coded cryptographic key)
- Compensating controls accepted: No
- Description: Group Policy Preferences (GPP) is the legacy Windows mechanism for distributing settings to domain machines via XML files in SYSVOL. Several GPP types -- Drives, Services, ScheduledTasks, DataSources -- have a `cpassword` attribute that stores a credential for the affected service. Microsoft encrypted the value with a hard-coded AES key documented in MSDN; the encryption is reversible by any authenticated domain user with SYSVOL read access. Microsoft published MS14-025 (KB2962486) which disables GPP cpassword reading and recommends purging existing cpassword-bearing XML.
- Attacker starting state: 10.20.30.10, `corp\alice:Password1!` (any authenticated user has SYSVOL read).
- Constraint: SYSVOL + GPO processing must remain functional. The Default Domain Policy and Default Domain Controllers Policy must keep returning from `Get-GPO`.
- Verification: behavioral SMB SYSVOL pull + grep for cpassword attribute; behavioral SYSVOL listing + `Get-GPO` enumeration.
- Expected remediation paths:
  1. Remove the SYSVOL Policies subdirectory containing the cpassword XML (`Remove-Item ... -Recurse -Force`).
  2. Rotate the password of any account whose credential was stored (svc_sql in the lab inject) since the cpassword is publicly recoverable.
  3. Apply MS14-025 (KB2962486) on all clients -- disables GPP cpassword reading at the policy-application layer.
