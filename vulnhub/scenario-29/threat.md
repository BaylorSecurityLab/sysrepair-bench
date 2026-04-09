# Custom Service Bound to All Interfaces

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
A custom service is bound to 0.0.0.0:8888 instead of localhost, exposing it to external
networks. Mirrors De-ICE S1.120 VulnHub VM.

## Affected Service
- **Binary:** /usr/local/bin/custom-service.sh
- **Port:** 8888/TCP

## Remediation Steps
1. Bind service to 127.0.0.1 only
2. Or add iptables rules restricting port 8888
