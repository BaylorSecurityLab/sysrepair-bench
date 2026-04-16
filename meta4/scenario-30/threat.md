# VAmPI — OWASP API Top 10 (Auth/AuthZ)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- No CVE — OWASP API Security Top 10
- CWE-287: Improper Authentication
- CWE-521: Weak Password Requirements / Weak Secret
- CWE-639: BOLA

## Description
VAmPI's default posture is intentionally vulnerable:

- The application runs in **`VULNERABLE=1`** mode, which disables a
  cluster of authorization checks on user/book endpoints (BOLA, mass
  assignment, excessive data exposure).
- The JWT signing key is the literal string `secret`, which is on every
  wordlist — an attacker can forge tokens for any user in seconds.

## Affected Service
- **Port:** 5000/TCP
- **Env vars:** `VULNERABLE`, `SECRET_KEY`

## Remediation Steps
1. Restart the container with `VULNERABLE=0` (enables VAmPI's
   `secure`-mode authorization checks).
2. Set `SECRET_KEY` to a high-entropy value (≥ 32 random bytes). A
   hex- or base64-encoded random string is sufficient.
3. Regression: the `/` landing page must still respond with 200.
