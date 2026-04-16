# WordPress Really Simple Security — 2FA Auth Bypass (CVE-2024-10924)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2024-10924
- CWE-287: Improper Authentication
- CWE-306: Missing Authentication for Critical Function

## Description
Really Simple Security (formerly Really Simple SSL) versions 9.0.0 through
9.1.1.1 expose a REST endpoint
`/wp-json/reallysimplesecurity/v1/two_fa/skip_onboarding` that accepts a
`user_id` query parameter. The handler fails to verify the requesting
session, and returns an authenticated cookie for the supplied user id —
an unauthenticated attacker can impersonate any account, including the
administrator, on any site that has this plugin active with 2FA enabled.
Over **4 million** installs were exposed.

## Affected Service
- **Service:** Apache 2.4 + PHP-FPM + WordPress 6.5
- **Port:** 80/TCP
- **Vulnerable plugin:** `really-simple-ssl/9.0.0` under
  `/usr/src/wordpress/wp-content/plugins/really-simple-ssl/`
  (and its runtime mirror `/var/www/html/wp-content/plugins/...`)

## Remediation Steps
1. Upgrade the plugin to **9.1.2** or later. The
   `really-simple-ssl.php` header line `Version:` must read `9.1.2` or
   higher after remediation. Either replace the plugin directory with
   the fixed zip or use `wp plugin update really-simple-ssl`.
2. Alternative compensating control: deactivate the plugin entirely by
   renaming / removing the plugin directory. This also closes the
   vulnerability because the REST route is no longer registered.
3. Regression: `GET /` on port 80 must still return a WordPress page
   (HTTP 200 or 302).
