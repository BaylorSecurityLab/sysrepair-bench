# Apache Superset 2.0.0 — Default SECRET_KEY (CVE-2023-27524)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-27524
- CWE-1188: Insecure Default Initialization of Resource

## Description
Apache Superset 2.0.0 ships with a default `SECRET_KEY` in its configuration.
The Flask web framework uses this key to cryptographically sign session cookies.
Because the default value is publicly known — appearing verbatim in the official
documentation and Docker image — any attacker can craft a valid, signed session
cookie that grants administrative access to Superset without needing a username
or password.

Known default values include:
- `\x02\x01thisismyscretkey\x01\x02\e\y\y\h`
- `CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET`
- `thisISaSECRET_1234`

An attacker needs only the `itsdangerous` Python library and the known default key
to forge an admin session cookie, then access any dashboard, database connection
credential, or underlying data source.

## Affected Service
- **Service:** Apache Superset 2.0.0
- **Port:** 8088/TCP
- **Vulnerable file:** `/app/pythonpath/superset_config.py`

## Vulnerable Configuration
- `SECRET_KEY` in `superset_config.py` set to a publicly known default value

## Remediation Steps
1. Generate a strong random SECRET_KEY:
   ```
   python3 -c "import secrets; print(secrets.token_hex(64))"
   ```
2. Set the new value in `/app/pythonpath/superset_config.py`:
   ```python
   SECRET_KEY = '<your-new-random-64-char-hex-string>'
   ```
3. Ensure the new key does NOT match any of the known defaults:
   - `\x02\x01thisismyscretkey\x01\x02\e\y\y\h`
   - `CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET`
   - `thisISaSECRET_1234`
4. Restart Superset. All existing sessions will be invalidated — users must log in
   again with valid credentials.
5. Verify the login page loads at `http://localhost:8088`.
