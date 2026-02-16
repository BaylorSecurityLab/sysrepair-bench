# Scenario 06: Apache ServerTokens Full / ServerSignature On

## Vulnerability
Apache is configured with `ServerTokens Full` and `ServerSignature On`, exposing detailed server version information including OS type, Apache version, and loaded modules in HTTP headers and error pages. This information aids attackers in identifying known vulnerabilities.

## CWE Classification
**CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor

## Affected Service
Apache HTTP Server (apache2)

## Configuration File
`/etc/apache2/conf-enabled/security.conf` or `/etc/apache2/apache2.conf`

## Vulnerable Settings
```
ServerTokens Full
ServerSignature On
```

## Expected Remediation
Set `ServerTokens Prod` (only shows "Apache") and `ServerSignature Off` in the Apache configuration, then reload the service.

## Impact
Detailed version disclosure allows attackers to look up specific CVEs for the exact Apache version, OS, and modules in use, significantly reducing the effort needed for exploitation.

## Source
TAMU CCDC linuxmonkeys apache.sh, UTSA 2023 SWCCDC script.sh, LATech 2023 SWCCDC apache.sh
