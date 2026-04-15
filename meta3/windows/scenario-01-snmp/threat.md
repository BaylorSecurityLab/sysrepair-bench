# SNMP Default 'public' Community String (Read-Write)

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness — tracked by CWE-521, CWE-798)

## Description
The SNMP service on this host is configured with the default community string `public` and
grants it **read-write** access (registry value `4` under `ValidCommunities`). In addition,
the `PermittedManagers` allow-list has been cleared, so the agent accepts SNMP requests
from any source address. Authentication traps are disabled, so brute-force attempts and
configuration changes are not logged to the SNMP trap receiver.

An unauthenticated remote attacker who can reach UDP/161 can:
- Enumerate installed software, running services, network interfaces, routing tables,
  listening TCP/UDP ports, and local user accounts via standard MIBs.
- **Write** arbitrary OIDs back to the agent, altering system configuration or interface
  state where the underlying MIB permits it.

This is the exact misconfiguration shipped by upstream Metasploitable3 via
`scripts/installs/setup_snmp.bat`.

## Affected Service
- **Service:** `SNMP`
- **Port:** 161/UDP
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters`

## Vulnerable Configuration
```
HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities
    public    REG_DWORD    0x00000004    (READ-WRITE)
HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers
    (empty — all managers permitted)
HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters
    EnableAuthenticationTraps    REG_DWORD    0x00000000
```

## Remediation Steps
1. Remove the `public` community entirely:
   ```
   reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" /v public /f
   ```
2. Re-enable authentication traps:
   ```
   reg add "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters" /v EnableAuthenticationTraps /t REG_DWORD /d 1 /f
   ```
3. Restrict `PermittedManagers` to the monitoring host(s) that legitimately poll this
   agent (add one `REG_SZ` entry per permitted manager IP or hostname, named `1`, `2`, ...).
4. Restart the SNMP service:
   ```
   Restart-Service SNMP
   ```
5. Longer-term: migrate to SNMPv3 (authPriv), which replaces community strings with
   per-user authentication and encryption.
