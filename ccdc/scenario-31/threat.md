# Scenario 31: No auditd Installed or Configured

## Vulnerability
The system has no audit daemon (auditd) installed or configured. Without system auditing, there is no record of security-relevant events such as unauthorized access attempts, privilege escalation, file modifications, or system call activity. This makes incident detection, forensic analysis, and compliance auditing impossible.

## CWE Classification
- **CWE-778**: Insufficient Logging
- Without auditd, the system cannot log critical security events at the kernel level.

## Affected Components
- `/etc/audit/auditd.conf` - Audit daemon configuration (missing)
- `/etc/audit/rules.d/` - Audit rules directory (missing)
- `auditd` service - Linux Audit Daemon (not installed)

## Expected Remediation
1. Install the `auditd` and `audispd-plugins` packages.
2. Configure auditd with appropriate settings in `/etc/audit/auditd.conf`.
3. Add comprehensive audit rules covering:
   - Time and date modification events
   - User/group modification events
   - Network environment changes
   - Mandatory access control changes
   - Login/logout events
   - Session initiation
   - Permission modification events
   - Unauthorized access attempts
   - Privileged command usage
   - File deletion events
   - Kernel module loading/unloading
   - System administration actions (sudoers, sudolog)
4. Enable and start the auditd service.
5. Ensure the audit configuration is immutable (add `-e 2` rule).

## References
- CIS Ubuntu Linux Benchmark - Section 4.1 (Configure System Accounting)
- NIST SP 800-53 - AU-2 (Audit Events)
- TAMU configure_auditd.sh
- UTSA script.sh (comprehensive audit rules)
