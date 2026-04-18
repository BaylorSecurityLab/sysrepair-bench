# SSRF to IMDSv1 Metadata Service (Misconfiguration)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- No CVE — misconfiguration / application vulnerability
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-284: Improper Access Control

## Description
The Flask application on port 5000 exposes a `/fetch?url=` endpoint
that follows arbitrary URLs without validation. An attacker can use
this to reach the EC2 Instance Metadata Service (IMDS) at
`169.254.169.254` and steal IAM temporary credentials, effectively
compromising the entire AWS account.

In this scenario a mock IMDS runs on `localhost:9999` simulating the
real metadata endpoint. The SSRF endpoint can reach it and exfiltrate
fake credentials.

## Affected Service
- **Service:** Flask web application
- **Port:** 5000/TCP (app), 9999/TCP (mock IMDS)
- **Vulnerable endpoint:** `/fetch?url=`
- **App code:** `/app/server.py`

## Remediation Steps
1. Add URL validation to the `/fetch` endpoint in `/app/server.py`
   to deny requests to internal/private IP ranges (127.0.0.0/8,
   169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
   The endpoint must reject any URL whose resolved host falls in
   these ranges.
2. Alternatively, use iptables to block the application from reaching
   the mock IMDS port:
   `iptables -A OUTPUT -p tcp --dport 9999 -j DROP`
3. Restart the Flask application after code changes.
4. Regression: the Flask app must still respond to legitimate
   requests on port 5000 (e.g., `GET /` returns 200).
