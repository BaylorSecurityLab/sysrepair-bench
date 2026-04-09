# SMTP (Exim4) Exposed on All Interfaces

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
Exim4 SMTP daemon is listening on all interfaces (0.0.0.0:25) with no firewall rules
restricting access. Mirrors DC-8 VulnHub VM.

## Affected Service
- **Service:** Exim4
- **Port:** 25/TCP
- **Configuration:** /etc/exim4/update-exim4.conf.conf

## Remediation Steps
1. Set `dc_local_interfaces='127.0.0.1'` in Exim4 config
2. Or add iptables rules to restrict port 25
3. Run `update-exim4.conf && service exim4 restart`
