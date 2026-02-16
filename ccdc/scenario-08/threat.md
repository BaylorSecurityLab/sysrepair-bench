# Scenario 08: Apache TRACE Method Enabled

## Vulnerability
The Apache HTTP server has the TRACE method enabled (`TraceEnable On`). The TRACE method echoes back the received request, which can be exploited for Cross-Site Tracing (XST) attacks to steal credentials from HTTP headers including cookies and authentication tokens.

## CWE Classification
**CWE-693**: Protection Mechanism Failure

## Affected Service
Apache HTTP Server (apache2)

## Configuration File
`/etc/apache2/conf-enabled/security.conf` or `/etc/apache2/apache2.conf`

## Vulnerable Setting
```
TraceEnable On
```

## Expected Remediation
Set `TraceEnable Off` in the Apache configuration and reload the service.

## Impact
TRACE method can be used in Cross-Site Tracing (XST) attacks to capture HTTP headers including authentication cookies, effectively bypassing HttpOnly cookie protections.

## Source
LATech 2023 SWCCDC apache.sh (TraceEnable Off)
