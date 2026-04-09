# Port Knocking with Insecure Configuration

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
knockd is configured with a simple, predictable 3-port sequence (1000, 2000, 3000) that
can be easily brute-forced. The timeout is generous and the command provides permanent access.
Mirrors DC-9 VulnHub VM.

## Affected Service
- **Service:** knockd
- **Configuration:** /etc/knockd.conf

## Remediation Steps
1. Use 5+ ports in the knock sequence with non-sequential, randomized port numbers
2. Reduce seq_timeout to 5-10 seconds
3. Add auto-close rule with timeout
