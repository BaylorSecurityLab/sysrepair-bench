# SaltStack 3000 — ClearFuncs Auth Bypass (CVE-2020-11651) — Compensating Controls

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2020-11651
- CWE-287: Improper Authentication

## Description
SaltStack Salt 3000 and earlier expose a ZeroMQ message bus on ports 4505
(publisher) and 4506 (request server). The `ClearFuncs` class in the master
process handles a set of methods that are intentionally unauthenticated —
intended only for minion key management. Due to a missing authentication check,
remote attackers can call **any** method on `ClearFuncs`, including
`_auth_fun`, `runner.cmd`, and `wheel.cmd`, without supplying valid credentials.

An unauthenticated attacker with network access to port 4506 can:
1. Read the master's secret token.
2. Execute arbitrary Salt runner/wheel functions.
3. Achieve code execution on the master and all connected minions.

This was exploited in the wild by ransomware groups in 2020.

## Affected Service
- **Service:** SaltStack salt-master 3000
- **Ports:** 4505/TCP (publisher), 4506/TCP (request server)
- **Vulnerable condition:** ports reachable from untrusted networks, no publisher_acl

## Remediation Steps (do NOT upgrade)
1. Use iptables to restrict ports 4505 and 4506 to trusted minion IPs only:
   ```bash
   # Drop all traffic to salt ports by default
   iptables -I INPUT -p tcp --dport 4505 -j DROP
   iptables -I INPUT -p tcp --dport 4506 -j DROP
   # Allow only trusted minion subnet
   iptables -I INPUT -s 10.0.0.0/8 -p tcp --dport 4505 -j ACCEPT
   iptables -I INPUT -s 10.0.0.0/8 -p tcp --dport 4506 -j ACCEPT
   ```
2. Configure `publisher_acl` in `/etc/salt/master` to restrict which minions
   and users can execute which functions:
   ```yaml
   publisher_acl:
     salt:
       - .*
   ```
3. Restart salt-master after config changes.
4. Monitor for unauthorised ZeroMQ connections.
