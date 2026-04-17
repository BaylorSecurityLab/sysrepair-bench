# Modbus/TCP — Unauthenticated PLC Access (protocol design flaw)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Category
Compensating Controls

## Description
Modbus/TCP is an industrial control system (ICS) protocol designed in 1979 for
serial communication and later adapted for TCP/IP networks. The protocol has
**no native authentication, encryption, or access control** — any host that
can reach TCP port 502 can send arbitrary Modbus commands.

In this scenario the Modbus server listens on `0.0.0.0:502`, meaning any
network-reachable client can read or write PLC holding registers without
credentials. An attacker can:
- Read sensor values and setpoints (reconnaissance)
- Write arbitrary register values to manipulate physical processes
- Cause equipment damage or safety incidents

Because the vulnerability is a protocol design flaw, it cannot be fixed in
software — compensating network-layer controls are required.

## Affected Service
- **Service:** pyModbusTCP simulated PLC
- **Port:** 502/TCP
- **Vulnerable configuration:** server bound to `0.0.0.0` with no firewall

## Remediation Steps
1. Apply an iptables allow-list that restricts port 502 to authorized
   engineering workstation IPs only, dropping all other traffic:
   ```
   iptables -A INPUT -p tcp --dport 502 -s <trusted-ip> -j ACCEPT
   iptables -A INPUT -p tcp --dport 502 -j DROP
   ```
2. Alternatively, bind the Modbus server to `127.0.0.1` only so it is not
   reachable from external interfaces.
3. Deploy the Modbus server on an isolated OT network VLAN with no direct
   internet or corporate LAN access.
4. Use a Modbus-aware firewall or IDS to detect anomalous read/write patterns.
