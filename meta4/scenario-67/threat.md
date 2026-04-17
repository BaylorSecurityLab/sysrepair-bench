# BACnet/IP — Unauthenticated Building Automation Access (protocol design flaw)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Category
Compensating Controls

## Description
BACnet (Building Automation and Control Networks) is an ASHRAE/ISO/ANSI
standard protocol for building automation systems — HVAC, lighting, access
control, fire detection. The standard UDP port is 47808 (0xBAC0).

BACnet has **no native authentication or encryption** by design. Any host that
can send UDP packets to port 47808 can:
- Enumerate all building automation devices (Who-Is broadcast)
- Read any object property: temperature setpoints, door states, alarm statuses
- Write properties to manipulate HVAC setpoints, unlock doors, disable fire alarms
- Send Out-of-Service commands to bypass sensor readings

A 2013 Project Basecamp study found over 25,000 BACnet devices directly
internet-accessible. When exposed on `0.0.0.0`, the BACnet server accepts
requests from any source without authentication or authorization checks.

## Affected Service
- **Service:** BACnet/IP server (simulated)
- **Port:** 47808/UDP
- **Vulnerable configuration:** server bound to `0.0.0.0` with no firewall

## Remediation Steps
1. Apply iptables rules to restrict UDP 47808 to the BMS (Building Management
   System) subnet CIDR only:
   ```
   iptables -A INPUT -p udp --dport 47808 -s <bms-subnet-cidr> -j ACCEPT
   iptables -A INPUT -p udp --dport 47808 -j DROP
   ```
2. Segment BACnet devices onto a dedicated building automation VLAN with no
   routed path to corporate networks or the internet.
3. Deploy a BACnet-aware firewall or gateway that enforces device whitelisting
   and blocks unauthorized Who-Is / Write-Property requests.
4. Where BACnet/SC (Secure Connect, ASHRAE 135-2020 Addendum bj) is supported,
   migrate to BACnet/SC which adds TLS 1.3 and certificate-based authentication.
