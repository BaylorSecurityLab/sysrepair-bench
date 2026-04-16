# Confluence Broken Access Control — Admin Creation (CVE-2023-22515)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2023-22515
- CWE-284: Improper Access Control

## Description
Confluence Data Center and Server versions 8.0.0 through 8.3.2,
8.4.0 through 8.4.2, and 8.5.0 through 8.5.1 can be forced back into
their initial-setup state by unauthenticated requests to
`/setup/setupadministrator.action` with a `trigger=true` query
parameter. Once the "setup complete" flag is cleared, an attacker can
POST to the administrator-creation endpoint and create a new admin
account, bypassing all authentication.

## Affected Service
- **Service:** Confluence Server 8.3.2
- **Port:** 8090/TCP

## Remediation Steps
1. Upgrade to **8.3.3**, **8.4.3**, **8.5.2**, or any later release.
2. Until upgraded, block the `/setup/` URL path at a reverse proxy or
   IP-restrict Confluence's administrative endpoints.
3. Regression: Confluence UI must still load on port 8090.
