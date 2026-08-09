# SNMP Default 'public' Community String (Read-Write)

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness — tracked by CWE-521, CWE-798)

## Description
The SNMP agent on this host is configured with the default community string `public` and
grants it **read-write** access over the whole `1.3.6` subtree. The agent is bound to
`0.0.0.0`, so it accepts SNMP requests from any source address, and it emits no
authentication traps, so brute-force attempts and configuration changes are not logged to
a trap receiver.

An unauthenticated remote attacker who can reach UDP/161 can:
- Enumerate installed software, running services, network interfaces, routing tables,
  listening TCP/UDP ports, and local user accounts via standard MIBs.
- **Write** arbitrary OIDs back to the agent, altering system configuration or interface
  state where the underlying MIB permits it.

This is the exact misconfiguration shipped by upstream Metasploitable3 via
`scripts/installs/setup_snmp.bat`. Note that this host is Server Core ltsc2019, which no
longer ships Windows' own SNMP service — there is no `SNMP` service and no
`HKLM\SYSTEM\CurrentControlSet\Services\SNMP` key on this box. The listener on UDP/161 is
a standalone **pysnmp** agent started from the host's boot script, and *that* is the
component carrying the weakness.

## Affected Service
- **Agent:** pysnmp SNMPv2c responder, `C:\snmp\snmp_agent.py`
- **Interpreter:** `C:\Python311\python.exe` (the agent runs as a detached child of the
  boot script, not as a registered Windows service)
- **Port:** 161/UDP, bound to `0.0.0.0`
- **Community:** `public`, READ-WRITE

## Vulnerable Configuration
```python
# C:\snmp\snmp_agent.py
config.addTransport(snmp_engine, udp.domainName,
                    udp.UdpTransport().openServerMode(('0.0.0.0', 161)))

# SNMPv2c with community 'public' - READ-WRITE (permits set-request).
config.addV1System(snmp_engine, 'rw-area', 'public')
config.addVacmUser(snmp_engine, 2, 'rw-area', 'noAuthNoPriv',
                   readSubTree=(1, 3, 6),
                   writeSubTree=(1, 3, 6))
```

## Remediation Steps
1. Retire the `public` community in the agent's own configuration
   (`C:\snmp\snmp_agent.py`). The community name is the third argument to
   `config.addV1System` and is referenced again by name in the `config.addVacmUser`
   call that grants it access — both must agree, or the agent will not answer at all.
   Replace it with a long random value that is not in any wordlist.
2. Drop write access. `writeSubTree=(1, 3, 6)` hands out SNMP SET over the entire OID
   tree; a monitoring poller only ever needs read. Removing the `writeSubTree` argument
   leaves a read-only view.
3. Restart the agent so the new configuration takes effect, and **leave UDP/161 bound** —
   monitoring depends on it, and simply killing the agent is not remediation:
   ```powershell
   Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
       Where-Object { $_.CommandLine -like '*snmp_agent.py*' } |
       ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
   Start-Process -FilePath 'C:\Python311\python.exe' `
       -ArgumentList 'C:\snmp\snmp_agent.py' -WindowStyle Hidden
   ```
4. Restrict who may poll the agent — pysnmp's transport can be bound to a specific
   management address instead of `0.0.0.0`, and the host firewall can limit UDP/161 to
   the monitoring host(s) that legitimately poll this agent.
5. Longer-term: migrate to SNMPv3 (authPriv), which replaces community strings with
   per-user authentication and encryption.
