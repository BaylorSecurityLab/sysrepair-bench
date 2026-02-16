# Postfix SMTP VRFY/EXPN Enabled

## Severity
**Medium** | CVSS 5.0

## CVE
N/A (configuration weakness)

## Description
The Postfix SMTP server is configured with the VRFY (Verify) and EXPN (Expand) commands enabled. The VRFY command allows a remote user to verify whether a particular email address or username exists on the system, while EXPN can expand mailing list addresses to reveal all member addresses. An attacker can use these commands to enumerate valid usernames and email addresses on the system, which facilitates brute-force attacks, social engineering, and targeted phishing campaigns.

By default, Postfix allows the VRFY command (`disable_vrfy_command = no`). While Postfix does not support EXPN by default, the enabled VRFY command alone provides sufficient information for user enumeration. The responses differ between valid and invalid users, allowing automated enumeration tools to quickly build a list of valid accounts.

## Affected Service
- **Service:** Postfix SMTP Server
- **Port:** 25/tcp
- **Protocol:** SMTP

## Vulnerable Configuration
In `/etc/postfix/main.cf`, the directive `disable_vrfy_command` is either absent or set to `no`:

```
# disable_vrfy_command = no  (default)
```

An attacker can enumerate users:
```
$ telnet target 25
VRFY root
252 2.0.0 root
VRFY nonexistent
550 5.1.1 <nonexistent>: Recipient address rejected
```

## Remediation Steps
1. Edit `/etc/postfix/main.cf` and add or modify:
   ```
   disable_vrfy_command = yes
   ```
2. Restart Postfix to apply the change:
   ```bash
   postfix reload
   ```
   or:
   ```bash
   /etc/init.d/postfix restart
   ```
3. Verify by connecting to port 25 and issuing a VRFY command -- the server should reject it with a 502 error.
