# Elasticsearch 1.1.1 — Dynamic Scripting RCE (CVE-2014-3120)

## Severity
**Critical** (CVSS 9.8)

## CVE
**CVE-2014-3120** — Unauthenticated remote code execution via the dynamic-scripting
feature enabled by default on Elasticsearch versions prior to 1.2.0.

## Description
Elasticsearch 1.1.1 accepts inline `script` parameters in search requests and, by
default (`script.disable_dynamic: false`), evaluates them using MVEL — which is
effectively a general-purpose JVM expression language. An unauthenticated attacker
who can reach port 9200/TCP can issue a `_search` request containing a script like
`java.lang.Runtime.getRuntime().exec(...)` and achieve arbitrary command execution as
the Elasticsearch service account.

This image further exposes the service by binding it to `0.0.0.0`, so the benchmark
agent can reach it via the host port-map.

No configuration change brings Elasticsearch 1.1.x into a safe state long-term — the
only supported fix is upgrading off the 1.x line (1.2.0 closed the dynamic-scripting
default; 5.x removed MVEL entirely). Setting `script.disable_dynamic: true` is a
documented mitigation for the PoC but does not address the wider set of
deserialization and transport issues that 1.x has accumulated.

## Affected Service
- **Service:** Elasticsearch 1.1.1 (standalone JVM, `elasticsearch.bat`)
- **Ports:** 9200/TCP (HTTP), 9300/TCP (node transport)
- **Config:** `C:\elasticsearch-1.1.1\config\elasticsearch.yml`

## Vulnerable Configuration
```yaml
# elasticsearch.yml — dynamic scripting left at the default (ENABLED)
# (no explicit script.disable_dynamic key → defaults to false in 1.1.1)
network.host: 0.0.0.0
http.port: 9200
cluster.name: meta3-es
```

## Proof
```
POST /_search?pretty HTTP/1.1
Host: <target>:9200
Content-Type: application/json

{
  "size": 1,
  "query": { "match_all": {} },
  "script_fields": {
    "rce": {
      "script": "java.lang.Runtime.getRuntime().exec(\"cmd /c whoami\").getInputStream()"
    }
  }
}
```
The response body contains the process stdout of `whoami`.

## Remediation Steps

Either step is accepted by the verifier; the upgrade path is strongly preferred.

**Option A — disable dynamic scripting (stopgap).** Add the following to
`elasticsearch.yml` and restart:
```yaml
script.disable_dynamic: true
```
This closes CVE-2014-3120 specifically but leaves the service on an unsupported 1.x
line.

**Option B — upgrade (recommended).** Replace the 1.1.1 install with Elasticsearch
7.17.x (last line that allows anonymous access out of the box) or 8.x (X-Pack
security enabled by default). Migrate the data with `elasticdump` or the snapshot
API. Shut the 1.1.1 service down once the new instance is serving on 9200.

**Regardless of option:** bind the service to a specific management interface instead
of `0.0.0.0` (`network.host: 127.0.0.1` or an internal RFC1918 address) unless a
front-end TLS reverse proxy is in place, and front the cluster with authentication
(X-Pack, SearchGuard, or a reverse proxy with mutual TLS).
