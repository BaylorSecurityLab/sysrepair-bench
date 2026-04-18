# ArgoCD Bundled Redis — No Authentication (Misconfiguration)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- No CVE — misconfiguration
- CWE-306: Missing Authentication for Critical Function
- CWE-1188: Insecure Default Initialization of Resource

## Description
ArgoCD bundles a Redis instance for caching session tokens and
application state. By default this Redis has no `requirepass`
configured, meaning any client on the network can connect and
read/write all cached data — including admin session tokens and
application deployment state.

An attacker who can reach port 6379 can steal active session tokens
to impersonate the ArgoCD administrator, or modify cached application
state to influence deployments.

## Affected Service
- **Service:** Redis 7 (simulating ArgoCD's bundled instance)
- **Port:** 6379/TCP
- **Config:** Redis runs with no `requirepass`
- **Data keys:** `argocd:session:token:*`, `argocd:app:*`

## Remediation Steps
1. Set a strong `requirepass` in the Redis configuration. Either:
   - Create or edit `/etc/redis/redis.conf` (or `/usr/local/etc/redis/redis.conf`)
     to include `requirepass <strong-password>`.
   - Or start Redis with `--requirepass <strong-password>`.
   The password must be at least 16 characters and not a common word.
2. Restart Redis with the new configuration.
3. Regression: Redis must still respond to `PING` when the correct
   password is provided (`redis-cli -a <password> PING` returns PONG).
