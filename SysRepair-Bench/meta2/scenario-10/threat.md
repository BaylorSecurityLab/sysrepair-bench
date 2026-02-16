# Apache TRACE/TRACK Methods Enabled

## Severity
**Medium** | CVSS 5.8

## CVE
CVE-2003-1567

## Description
The Apache HTTP server is configured with the TRACE (and/or TRACK) HTTP method enabled. The TRACE method echoes back the full HTTP request, including headers, in the response body. An attacker can exploit this via Cross-Site Tracing (XST) to steal sensitive information such as cookies marked HttpOnly, authorization headers, and other credentials. When combined with a cross-site scripting (XSS) vulnerability or a client-side exploit, TRACE allows an attacker to bypass HttpOnly cookie protections and capture session tokens.

Apache 2.2 ships with `TraceEnable On` by default, making it vulnerable out of the box.

## Affected Service
- **Service:** Apache HTTP Server 2.2
- **Port:** 80/tcp
- **Protocol:** HTTP

## Vulnerable Configuration
In `/etc/apache2/apache2.conf`, the directive `TraceEnable On` is present (or absent, since On is the default):

```
TraceEnable On
```

A TRACE request like the following returns the full request headers in the response body:
```
TRACE / HTTP/1.1
Host: target
```

## Remediation Steps
1. Edit the Apache configuration file (`/etc/apache2/apache2.conf` or an appropriate conf file):
   ```
   TraceEnable Off
   ```
2. Restart Apache to apply the change:
   ```
   apache2ctl restart
   ```
3. Verify by sending a TRACE request -- the server should return 405 Method Not Allowed or 403 Forbidden.
