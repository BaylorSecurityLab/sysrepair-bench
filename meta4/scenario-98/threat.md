# Apache Druid 0.20.2 — JavaScript Injection RCE (CVE-2021-25646)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CVE-2021-25646
- CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
Apache Druid 0.20.2, when JavaScript is enabled (`druid.javascript.enabled=true`),
allows users to supply JavaScript function bodies in query filter expressions via
the DataSource endpoint. These expressions are executed directly by the Druid
server's JavaScript engine (Rhino) with the privileges of the `druid` process.

An attacker with network access to the coordinator (port 8081) can send a crafted
HTTP POST request with a malicious JavaScript payload in the `filter` field of a
native query. No authentication is required in default deployments. The payload
is executed on the server immediately, enabling arbitrary OS command execution:

```json
{
  "queryType": "scan",
  "dataSource": "wikipedia",
  "filter": {
    "type": "javascript",
    "dimension": "added",
    "function": "function(value) { java.lang.Runtime.getRuntime().exec('id > /tmp/pwned'); return true; }"
  }
}
```

## Affected Service
- **Service:** Apache Druid 0.20.2 (coordinator)
- **Port:** 8081/TCP
- **Vulnerable configuration:** `druid.javascript.enabled=true`

## Vulnerable Configuration
- `druid.javascript.enabled=true` in `runtime.properties`

## Remediation Steps (do NOT upgrade)
1. Set `druid.javascript.enabled=false` in the coordinator's `runtime.properties`:
   ```
   druid.javascript.enabled=false
   ```
   The file is located at:
   `$DRUID_HOME/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties`
2. Restart the Druid coordinator for the change to take effect.
3. Verify the setting is in place:
   ```
   grep druid.javascript.enabled $DRUID_HOME/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties
   ```
4. Confirm the coordinator is still responsive on port 8081.
