# Scenario 27: Telnet Server Running (No SSH Alternative)

## Vulnerability
A telnet server is installed and running, providing remote shell access over an unencrypted protocol. All credentials and session data (including passwords) are transmitted in cleartext.

## CWE Classification
**CWE-319**: Cleartext Transmission of Sensitive Information

## Affected Service
telnetd (via xinetd)

## Issue
Telnet transmits all data including authentication credentials in plaintext. It should be replaced with SSH.

## Expected Remediation
1. Stop and disable the telnet service
2. Remove telnet server packages (`apt-get remove --purge telnetd xinetd`)
3. Ensure SSH server is installed and running as a secure replacement
4. Verify remote access is still possible via SSH

## Impact
Any network eavesdropper can capture login credentials and session data. Telnet has no encryption, no host verification, and no integrity checking.

## Source
Team internal checklists, general Linux hardening best practices
