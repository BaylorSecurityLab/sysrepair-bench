# RocketMQ 5.1.0 — Unauthenticated Config RCE (CVE-2023-33246)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-33246
- CWE-306: Missing Authentication for Critical Function

## Description
Apache RocketMQ 5.1.0 exposes a broker administration port (default 10911)
that accepts `UPDATE_BROKER_CONFIG` commands without any authentication when
ACL is disabled. An attacker with network access to this port can send a
crafted `UPDATE_BROKER_CONFIG` request to modify the broker's `filterServerNums`
and `rocketmqHome` properties. The broker will then start a filter server
process using the attacker-controlled path, achieving unauthenticated remote
code execution as the broker user.

The attack chain:
1. Attacker sends `UPDATE_BROKER_CONFIG` to port 10911 setting
   `filterServerNums=1` and `rocketmqHome=<attacker-controlled-path>`
2. Broker launches a filter server subprocess using the attacker's path
3. Attacker's binary executes as the `rocketmq` process user

No credentials are required. Public PoC scripts exist that automate this
attack in a single command.

## Affected Service
- **Service:** Apache RocketMQ 5.1.0
- **Ports:** 10911/TCP (broker administration), 9876/TCP (NameServer)
- **Vulnerable component:** Broker administration command handler, ACL disabled

## Vulnerable Configuration
- `aclEnable=false` in `broker.conf`
- Port 10911 accessible from untrusted networks
- No iptables rules restricting access to the broker administration port

## Remediation Steps
1. Enable ACL enforcement in `broker.conf` to require authentication for all
   admin commands:
   ```
   aclEnable=true
   ```
   Then create `/opt/rocketmq/conf/plain_acl.yml` with strong admin credentials:
   ```yaml
   accounts:
     - accessKey: adminKey
       secretKey: <strong-secret>
       whiteRemoteAddress: ''
       admin: true
   ```
2. Restrict access to port 10911 via iptables so that only trusted broker IPs
   and admin hosts can reach the administration port:
   ```
   iptables -I INPUT -p tcp --dport 10911 -s <trusted-admin-cidr> -j ACCEPT
   iptables -I INPUT -p tcp --dport 10911 -j DROP
   ```
3. Similarly restrict port 9876 (NameServer) to only known broker and client
   hosts:
   ```
   iptables -I INPUT -p tcp --dport 9876 -s <trusted-cidr> -j ACCEPT
   iptables -I INPUT -p tcp --dport 9876 -j DROP
   ```
4. Set `autoCreateTopicEnable=false` in `broker.conf` to prevent unauthenticated
   topic creation if ACL is later bypassed.
5. Verify that the RocketMQ NameServer still responds on port 9876 after
   applying firewall rules, confirming the service remains operational for
   legitimate clients.
