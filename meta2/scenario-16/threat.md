# vsftpd 2.3.4 Backdoor (Smiley Face Backdoor)

## Severity
**High** -- CVSS 7.5

## CVE
N/A (Supply chain compromise, not assigned a formal CVE)

## Description
The vsftpd 2.3.4 source tarball distributed from the official site between June 30 and July 1, 2011 was compromised. The backdoor code checks if the FTP username contains a smiley face (`:)`) and, if so, opens a listening shell on TCP port 6200. Any attacker who can reach port 21 can trigger remote root-level command execution on port 6200 without valid credentials.

This scenario simulates the backdoor by running a netcat listener on port 6200 alongside the vsftpd service, replicating the behavior that vulnerability scanners detect.

## Affected Service / Port
- **Service:** vsftpd (FTP)
- **Ports:** 21 (FTP), 6200 (backdoor shell)

## Vulnerable Version
- vsftpd 2.3.4 (compromised source tarball)

## Remediation Steps
1. Stop the backdoor listener process on port 6200.
2. Remove the backdoor script (`/usr/local/bin/backdoor.sh`).
3. Replace the compromised vsftpd with a clean version from the package manager:
   ```bash
   apt-get install --reinstall vsftpd
   ```
4. Remove the spoofed banner referencing version 2.3.4 from `/etc/vsftpd.conf` (remove or change the `ftpd_banner` line).
5. Ensure no process is listening on port 6200.
6. Restart the vsftpd service and verify FTP functionality.
