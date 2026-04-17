# Neo4j 3.4 — Shell Server RMI Deserialization RCE (CVE-2021-34371)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-34371
- CWE-502: Deserialization of Untrusted Data

## Description
Neo4j 3.4 ships with the Neo4j Shell Server feature that exposes a Java RMI
registry on port 1337. The Shell Server is intended for interactive
administration from the command line but, when `dbms.shell.enabled=true` and
`dbms.shell.host=0.0.0.0` are set, the RMI listener is reachable from any
network client.

CVE-2021-34371 exploits the RMI endpoint by sending a crafted serialized Java
object. The Neo4j runtime deserializes the payload without verifying its
origin or integrity, which triggers arbitrary code execution in the JVM before
any authentication check occurs. An attacker with TCP access to port 1337 can
achieve remote code execution as the `neo4j` OS user using a standard Java
deserialization gadget chain (e.g., via ysoserial):

```
java -jar ysoserial.jar CommonsCollections6 "id > /tmp/pwned" | \
    nc <host> 1337
```

No Neo4j credentials are required. The RMI handshake alone is sufficient to
deliver the malicious payload.

## Affected Service
- **Service:** Neo4j Community 3.4
- **Port:** 1337/TCP (RMI Shell Server), 7474/TCP (Browser HTTP), 7687/TCP (Bolt)
- **Vulnerable configuration:** `dbms.shell.enabled=true` with `dbms.shell.host=0.0.0.0`

## Vulnerable Configuration
- `NEO4J_dbms_shell_enabled=true` (or `dbms.shell.enabled=true` in `neo4j.conf`)
- `NEO4J_dbms_shell_host=0.0.0.0` (Shell Server bound to all interfaces)
- RMI port 1337 reachable from untrusted networks

## Remediation Steps
1. Disable the Shell Server entirely in `neo4j.conf`:
   ```
   dbms.shell.enabled=false
   ```
   If using environment variables, unset `NEO4J_dbms_shell_enabled` or set it
   to `false`.
2. Restart Neo4j to unbind the RMI port:
   ```
   neo4j restart
   ```
3. Block external access to port 1337 with an iptables rule as a defence-in-
   depth measure, even after the feature is disabled:
   ```
   iptables -A INPUT -p tcp --dport 1337 -j DROP
   ```
4. Confirm that port 1337 is no longer listening:
   ```
   ss -tlnp | grep ':1337'
   # expected: no output
   ```
5. Verify that the Neo4j Browser and Bolt endpoint remain operational:
   ```
   curl -s http://localhost:7474/
   # expected: HTTP 200 with Neo4j discovery JSON
   ```
