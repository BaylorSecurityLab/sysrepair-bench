# Binaries with Dangerous Linux Capabilities

## Severity
**High** (CVSS 7.8)

## CVE
N/A (configuration weakness)

## Description
Non-essential binaries have dangerous Linux capabilities: python3 has cap_dac_read_search
(read any file), find has cap_setuid (change UID). Mirrors De-ICE S1.130 VulnHub VM.

## Affected Service
- **Binaries:** /usr/bin/python3.7, /usr/bin/find

## Remediation Steps
1. Remove capabilities: `setcap -r /usr/bin/python3.7`
2. `setcap -r /usr/bin/find`
3. Audit with `getcap -r / 2>/dev/null`
