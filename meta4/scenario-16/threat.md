# JetBrains TeamCity Auth Bypass → RCE (CVE-2023-42793)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-42793
- CWE-288: Authentication Bypass Using an Alternate Path

## Description
TeamCity On-Premises versions prior to 2023.05.4 expose a code path that
allows an unauthenticated attacker to create an administrator API token:

```
POST /app/rest/users/id:1/tokens/RPC2
```

Returns a valid API token with administrator scope. With that token the
attacker can create a new admin user, modify build configurations, inject
build steps that execute arbitrary shell commands, or dump stored agent
credentials. This chain was weaponized in 2023 by APT29.

## Affected Service
- **Service:** JetBrains TeamCity On-Premises 2023.05.3
- **Port:** 8111/TCP

## Remediation Steps
1. Upgrade TeamCity to **2023.05.4** or later. (JetBrains also published
   a standalone security patch plugin for installations that cannot
   immediately upgrade.)
2. Until upgraded, restrict network access to the TeamCity web port
   (8111) to trusted management networks only (compensating control).
3. Verify the web UI still responds on port 8111.
