# Apache CGI Shellshock Vulnerability

## Severity
**Critical** (CVSS 10.0)

## CVE
CVE-2014-6271

## Description
Apache CGI scripts use Bash to process requests. If the Bash binary is vulnerable to
Shellshock, environment variables from HTTP headers can be evaluated as executable code.
Mirrors SickOs 1.1 VulnHub VM.

## Affected Service
- **Service:** Apache + mod_cgi + Bash
- **Port:** 80/TCP
- **Configuration:** /usr/lib/cgi-bin/

## Remediation Steps
1. Update Bash: `apt-get update && apt-get install -y bash`
2. Verify: `env x='() { :;}; echo vulnerable' bash -c "echo test"` should NOT print "vulnerable"
3. Alternatively disable mod_cgi if not needed
