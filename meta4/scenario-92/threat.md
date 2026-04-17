# Prometheus 2.40.0 — Unauthenticated Metrics Endpoint (misconfig)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Description
Prometheus 2.40.0, when started without a `--web.config.file`, exposes all HTTP
endpoints — including `/metrics` and `/api/v1/targets` — without requiring any
authentication. Any client that can reach port 9090 can retrieve a full inventory
of monitored targets, job names, label sets, and internal Prometheus performance
metrics. This leaks the complete infrastructure topology: hostnames, IP addresses,
service names, and the scrape configuration of every monitored system.

An attacker can silently enumerate the entire monitored estate with a single request:
```
curl http://prometheus-host:9090/api/v1/targets
```

This represents a significant reconnaissance advantage and can facilitate more
targeted follow-on attacks against exposed services.

## Affected Service
- **Service:** Prometheus 2.40.0
- **Port:** 9090/TCP
- **Vulnerable endpoints:** `/metrics`, `/api/v1/targets`, `/api/v1/query`, etc.

## Vulnerable Configuration
- Prometheus started without `--web.config.file`; all endpoints unauthenticated

## Remediation Steps
1. Create a `web.yml` configuration file enabling HTTP basic authentication:
   ```yaml
   basic_auth_users:
     admin: <bcrypt-hashed-password>
   ```
   Generate the bcrypt hash with: `htpasswd -nBC 12 admin`
2. Start Prometheus with `--web.config.file=/etc/prometheus/web.yml` so that
   all HTTP endpoints require credentials.
3. Verify that unauthenticated requests are rejected:
   ```
   curl http://localhost:9090/metrics   # must return 401
   ```
4. Verify that authenticated requests still succeed:
   ```
   curl -u admin:pass http://localhost:9090/metrics  # must return 200
   ```
