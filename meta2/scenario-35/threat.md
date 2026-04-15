# TWiki / Tiki Wiki Legacy Admin Exposure — Compensating Control

## Severity
**High** — multiple CVEs (TWikiDraw/MAKETEXT RCE CVE-2008-5304, Tiki Wiki <4.x auth bypass, etc.)

## Category
Compensating Controls (major-version wiki upgrade breaks site content and plugin surface)

## Description
Metasploitable 2 exposes TWiki 01.Feb.2003 and Tiki Wiki 1.9.5 on port 80. These codebases
have been abandoned in their 1.x form; the only upstream "fix" is a major-version upgrade
that rewrites URLs, breaks installed plugins, and forces data migration — unacceptable for
an archival wiki that must keep serving historical content.

The compensating-control task is to:
1. **Preserve** public read access (`/twiki/bin/view/*`).
2. **Block** the dangerous admin / debug / configure surface that hosts the RCE and auth-
   bypass findings (`/twiki/bin/configure`, `*/bin/edit`, `*/tiki-install.php`, etc.) at the
   web-server layer, via IP allowlist, HTTP auth, or ModSecurity-style location blocks.

## Affected Service / Port
- Apache serving legacy TWiki/Tiki binaries
- Port 80/TCP

## Remediation (compensating control)
Add a location block to Apache that denies external access to admin endpoints while public
view endpoints keep working:

```apache
# /etc/apache2/conf.d/twiki-lockdown.conf
<LocationMatch "^/twiki/bin/(configure|edit|rename|save|upload|login|manage)">
    Order deny,allow
    Deny from all
    Allow from 127.0.0.1
</LocationMatch>
```

Then reload Apache:
```bash
apache2ctl restart
```

Verify:
- `curl http://host/twiki/bin/configure` → **403**
- `curl http://host/twiki/bin/view` → **200** with body `TWIKI_VIEW_OK`

## Out of Scope
- Upgrading TWiki/Tiki to a supported major version (breaks content/plugins).
- Removing the wiki entirely.
