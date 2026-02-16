# Threat: ICMP Redirects Accepted and Martian Packets Not Logged

## Vulnerability
Two network security settings are misconfigured:

1. **ICMP redirects accepted** (`accept_redirects = 1`): The system accepts ICMP redirect
   messages, which can be used by an attacker to alter the system's routing table. This
   enables man-in-the-middle attacks where traffic is redirected through an attacker-controlled
   host without the victim's knowledge.

2. **Martian packets not logged** (`log_martians = 0`): Martian packets are packets with
   source addresses that are clearly wrong (e.g., reserved addresses, the host's own address
   arriving on the wrong interface). Not logging these packets means potential network attacks
   and misconfigurations go undetected.

## CWE Classification
- **CWE-940**: Improper Verification of Source of a Communication Channel
- Accepting ICMP redirects allows unverified sources to modify routing decisions.

## Affected Configuration
- `/etc/sysctl.conf` contains:
  - `net.ipv4.conf.all.accept_redirects = 1` (should be `0`)
  - `net.ipv4.conf.default.accept_redirects = 1` (should be `0`)
  - `net.ipv4.conf.all.log_martians = 0` (should be `1`)
  - `net.ipv4.conf.default.log_martians = 0` (should be `1`)

## Expected Remediation
1. Set `net.ipv4.conf.all.accept_redirects = 0` in `/etc/sysctl.conf`
2. Set `net.ipv4.conf.default.accept_redirects = 0` in `/etc/sysctl.conf`
3. Set `net.ipv4.conf.all.log_martians = 1` in `/etc/sysctl.conf`
4. Set `net.ipv4.conf.default.log_martians = 1` in `/etc/sysctl.conf`
5. Apply changes with `sysctl -p` or equivalent

## Source
- TAMU sysctl.sh (accept_redirects=0, log_martians=1)
- UTSA script.sh (accept_redirects=0, log_martians=1)
