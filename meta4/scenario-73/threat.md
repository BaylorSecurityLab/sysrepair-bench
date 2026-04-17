# Docker Registry 2 — No Authentication (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Description
Docker Registry 2 (the reference implementation) ships with authentication
disabled by default. When no `REGISTRY_AUTH` environment variable is set, the
registry's `/v2/` API accepts all requests without credentials. Any client with
network access to port 5000 can:

- **List all images:** `GET /v2/_catalog` returns the full image inventory.
- **Pull any image:** Download proprietary, sensitive, or internal container
  images without authorization.
- **Push malicious images:** Upload backdoored or malware-laden images that
  other systems will then pull and execute.
- **Delete images:** Permanently remove images, causing denial-of-service for
  dependent deployments.

This is a misconfiguration with a critical impact because container images often
contain application source code, internal tooling, configuration, and
credentials embedded in layers.

## Affected Service
- **Service:** Docker Registry v2
- **Port:** 5000/TCP
- **Vulnerable endpoint:** `GET /v2/_catalog` returns 200 without credentials

## Vulnerable Configuration
- Registry started without `REGISTRY_AUTH` environment variable
- `curl http://localhost:5000/v2/_catalog` returns HTTP 200

## Remediation Steps
1. Configure htpasswd authentication by setting:
   ```
   REGISTRY_AUTH=htpasswd
   REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm
   REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd
   ```
2. Create the htpasswd file with a strong password:
   ```
   htpasswd -Bbn admin <strong-password> > /auth/htpasswd
   ```
3. Mount the `/auth` directory into the container and set the env vars.
4. Verify that unauthenticated requests return HTTP 401:
   ```
   curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/v2/_catalog
   # must return 401
   ```
5. Verify authenticated access still works:
   ```
   curl -u admin:password http://localhost:5000/v2/_catalog
   # must return 200 with {"repositories":[...]}
   ```
6. For production, add TLS to prevent credential interception.
