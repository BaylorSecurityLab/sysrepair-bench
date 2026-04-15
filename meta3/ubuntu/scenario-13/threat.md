# Drupal 7.31 Pinned — mod_security WAF Blocking Drupalgeddon Payload (Compensating Control)

## Severity
**Critical** (CVSS 9.3) — vulnerability; WAF reduces exploitability to Medium

## CVE
CVE-2014-3704 ("Drupalgeddon")

## Category
Compensating Control — Drupal cannot be upgraded to 7.32+ because a legacy
module in this environment is incompatible with the patched database abstraction
layer. The agent must leave Drupal 7.31 in place and apply a network-layer
control that blocks the known attack payloads.

## Description
Drupal 7.31 is vulnerable to CVE-2014-3704 (Drupalgeddon), a SQL injection
flaw in `includes/database/database.inc` that allows unauthenticated remote
code execution. Because this deployment has a hard dependency on a module that
breaks under Drupal 7.32+, upgrading the core is forbidden.

The compensating control required is an Apache `mod_security` (ModSecurity) WAF
rule set that detects and blocks the distinctive Drupalgeddon payload shapes:
- POST body key pattern: `name[0 ;...]=` (space-semicolon array injection)
- Query-string pattern: `q[%23post_render][]=` (PHP callback registration)

The rule must block these payloads while allowing legitimate Drupal form
submissions (e.g., node/add, user login) to pass through unimpeded.

## Affected Service
- **Service:** Apache2 + Drupal 7.31 (pinned)
- **Port:** 80/TCP
- **Path:** `/drupal/`

## Constraint
Drupal must remain at version 7.31. The remediation must not upgrade, remove, or
disable the Drupal application. Only network-layer or Apache-layer controls are
permitted.

## Remediation Steps
1. Install ModSecurity and enable it:
   ```bash
   apt-get install -y libapache2-mod-security2
   a2enmod security2
   cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
   sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
   ```

2. Create a custom rule file blocking the Drupalgeddon payload shapes:
   ```bash
   cat > /etc/modsecurity/drupalgeddon.conf <<'EOF'
   # Block Drupalgeddon CVE-2014-3704 payload — POST body key injection
   SecRule ARGS_NAMES "@rx name\[0\s*;" \
     "id:9001,phase:2,deny,status:403,log,msg:'Drupalgeddon SQLi attempt (name array)'"

   # Block Drupalgeddon CVE-2014-3704 payload — post_render callback registration
   SecRule QUERY_STRING "@rx %23post_render" \
     "id:9002,phase:1,deny,status:403,log,msg:'Drupalgeddon SQLi attempt (post_render)'"
   EOF
   ```

3. Include the rule file from `modsecurity.conf` (or place it in
   `/etc/modsecurity/` where the wildcard `Include` picks it up):
   ```bash
   echo 'Include /etc/modsecurity/drupalgeddon.conf' \
     >> /etc/modsecurity/modsecurity.conf
   ```

4. Reload Apache:
   ```bash
   service apache2 reload
   ```

5. Verify the payload is blocked (must return 403) and the homepage still loads
   (must return 200).

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-13/Dockerfile -t meta3u-s13 .
docker run -d --name meta3u-s13 -p 8080:80 meta3u-s13
docker exec meta3u-s13 /bin/bash /verify.sh
docker stop meta3u-s13 && docker rm meta3u-s13
```
