# Hadoop YARN — Unauthenticated ResourceManager RCE (CWE-306)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- No single CVE (well-known misconfig, widely exploited in the wild)
- CWE-306: Missing Authentication for Critical Function

## Description
The Hadoop YARN ResourceManager exposes a REST API on port 8088. When
`yarn.acl.enable` is `false` (the default), there is no authentication
or authorisation on this endpoint. Any unauthenticated client can:

1. List running applications via `GET /ws/v1/cluster/apps`
2. Submit a new YARN application via `POST /ws/v1/cluster/apps` with an
   arbitrary shell command as the application master launch command.
3. The NodeManager executes the supplied command as the `yarn` OS user,
   providing unauthenticated remote code execution on every cluster node.

This misconfiguration has been exploited at scale to deploy cryptominers.

```bash
# PoC: submit a reverse shell as a YARN application
curl -s -X POST http://<host>:8088/ws/v1/cluster/apps \
  -H 'Content-Type: application/json' \
  -d '{"application-name":"pwn","am-container-spec":{"commands":{"command":"id > /tmp/pwned"}},"application-type":"YARN"}'
```

## Affected Service
- **Service:** Hadoop YARN ResourceManager
- **Port:** 8088/TCP (REST API)
- **Vulnerable configuration:** `yarn.acl.enable=false` (default)

## Vulnerable Configuration
- `yarn.acl.enable=false` in `yarn-site.xml`
- No Kerberos principal configured
- Port 8088 exposed to untrusted networks

## Remediation Steps (do NOT upgrade)
1. Enable ACL enforcement in `yarn-site.xml`:
   ```xml
   <property>
     <name>yarn.acl.enable</name>
     <value>true</value>
   </property>
   <property>
     <name>yarn.admin.acl</name>
     <value>yarn</value>
   </property>
   ```
2. Use iptables to restrict port 8088 to trusted admin subnets:
   ```bash
   iptables -I INPUT -p tcp --dport 8088 -j DROP
   iptables -I INPUT -s 10.0.0.0/8 -p tcp --dport 8088 -j ACCEPT
   ```
3. For production: enable Kerberos (`hadoop.security.authentication=kerberos`).
4. Restart the ResourceManager after config changes.
