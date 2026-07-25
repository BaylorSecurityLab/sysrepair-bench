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
The image ships a Shellshock-vulnerable `bash 4.3.0` built from source at `/bin/bash`, while
the distro's patched bash package is still recorded in dpkg. So restore the patched binary:

1. Reinstall bash from the distro package — a plain `apt-get install bash` is a no-op here
   because dpkg already believes bash is up to date, so **force the reinstall**:
   ```
   apt-get update && apt-get install -y --reinstall bash
   ```
2. Verify the parser bug is gone (must NOT print "vulnerable"):
   ```
   env x='() { :;}; echo vulnerable' /bin/bash -c "echo test"
   ```
   No service restart is required — `mod_cgi` forks a fresh bash per request, so the patched
   binary takes effect on the next HTTP request immediately.

> Note: disabling `mod_cgi` does **not** remediate this scenario — the verifier also probes
> `/bin/bash` directly, so the vulnerable shell must actually be replaced.
