# Scenario 29: No Firewall Installed (ufw Absent)

## Vulnerability
The system has no firewall installed or configured. All network ports are exposed directly without any filtering, allowing unrestricted inbound and outbound network access.

## CWE Classification
**CWE-1188**: Insecure Default Initialization of Resource

## Affected Service
System-wide (no firewall)

## Issue
Without a firewall, all running services are directly accessible from the network. There is no defense-in-depth against unauthorized access.

## Expected Remediation
1. Install ufw: `apt-get install ufw`
2. Set default deny incoming: `ufw default deny incoming`
3. Set default allow outgoing: `ufw default allow outgoing`
4. Allow necessary services: `ufw allow ssh`, `ufw allow http`
5. Enable ufw: `ufw enable`

## Impact
All services are exposed to the network without any filtering. An attacker can directly access any listening port, and compromised applications have unrestricted outbound network access.

## Source
TAMU CCDC linuxmonkeys firewall.sh (ufw default deny, allow specific ports)
