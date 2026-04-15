# Oracle GlassFish 4.0 — Admin Traversal + Exposed Admin Listener with Empty Password

## Severity
**Critical** (CVSS 9.8)

## CVE
- **CVE-2017-1000028** — Unauthenticated directory-traversal (`%c0%ae%c0%ae/`) on the
  admin listener allows arbitrary file read, including `domain.xml` / master-password
  files and ultimately the admin credentials themselves.
- Compounding weakness: **empty admin password** + secure-admin enabled → remote
  administrative access once traversal or brute-force reveals the realm is unlocked.

## Description
GlassFish 4.0 shipped an HTTP handler that decoded overlong UTF-8 byte sequences (e.g.
`%c0%ae` for `.`) **before** the path-normalization check. A single GET request to
`/theme/META-INF/prototype%c0%ae%c0%ae/%c0%ae%c0%ae/.../<any-file>` on the admin
listener returns the raw contents of that file relative to the `glassfish/domains/`
directory — all without authentication.

This host makes the impact worse by:
- Enabling **secure admin**, which moves the admin listener from `127.0.0.1:4848` to
  `0.0.0.0:4848` so it is reachable from any network peer.
- Leaving the admin realm user (`admin`) with an **empty password**, so once traversal
  discovers the realm configuration — or once an attacker simply tries
  `admin:""` — full administrative access is granted.

This reproduces the configuration baked by upstream Metasploitable3
(`scripts/installs/setup_glassfish.bat` + the bundled `admin-keyfile` / `domain.xml`).

## Affected Service
- **Service:** Oracle GlassFish 4.0 (`domain1`)
- **Ports:** 4848/TCP (admin), 8080/TCP (applications)
- **Config:** `C:\glassfish4\glassfish\domains\domain1\config\{domain.xml,admin-keyfile}`

## Vulnerable Configuration
```
<domain ...>
  <secure-admin-enabled>true</secure-admin-enabled>   <!-- admin reachable on 0.0.0.0 -->
</domain>
```
```
# admin-keyfile — admin user with empty password hash
admin;AS9-SHA256$1$...(empty-password hash)...
```
No patched build of GlassFish exists (Oracle discontinued the OSS track); CVE-2017-1000028
is unfixed on the 4.x line.

## Proof
```
# 1. Traversal read of domain.xml
curl --path-as-is \
  "http://<target>:4848/theme/META-INF/prototype%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/domain.xml"

# 2. Log in as admin with an empty password over the secure-admin REST API
curl -u admin: "http://<target>:4848/management/domain"
```

## Remediation Steps

All three steps are required (the verifier checks for the admin-listener binding and
the empty password; shutting GlassFish down is an acceptable PoC fix for a benchmark
run but is not real-world remediation).

1. **Set a strong admin password.** Start `domain1`, then:
   ```powershell
   & $env:GLASSFISH_HOME\bin\asadmin.bat --user admin change-admin-password
   # supply the empty current password, then a strong new one
   ```
2. **Disable secure-admin so 4848 binds to 127.0.0.1 only.** Reverse the listener
   exposure:
   ```powershell
   & $env:GLASSFISH_HOME\bin\asadmin.bat --user admin disable-secure-admin
   & $env:GLASSFISH_HOME\bin\asadmin.bat --user admin restart-domain domain1
   ```
3. **Migrate off GlassFish 4.0.** Oracle does not ship security fixes for the 4.x
   line. Long-term the server should be replaced with Payara 5.x / 6.x or another
   actively maintained Jakarta EE runtime — that is the only path that closes
   CVE-2017-1000028. Until migration completes, a reverse proxy that blocks the
   overlong-UTF-8 `%c0%ae` byte sequence on `/theme/` paths is an acceptable
   compensating control.
