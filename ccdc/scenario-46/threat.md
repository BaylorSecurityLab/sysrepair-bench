# Scenario 46: No Password Aging Policy

## Vulnerability
The system's password aging policy in `/etc/login.defs` has been configured with insecure values:
- `PASS_MAX_DAYS 99999` -- passwords essentially never expire (~274 years)
- `PASS_MIN_DAYS 0` -- passwords can be changed immediately with no minimum age
- `PASS_WARN_AGE 0` -- users receive no warning before password expiration

Without proper password aging, compromised credentials can be used indefinitely. The lack of a minimum password age also allows users to cycle through password changes to return to their original password, defeating password history policies.

## CWE Classification
- **CWE-263**: Password Aging with Long Expiration

## Impact
- **Credential Persistence**: Compromised passwords remain valid indefinitely without forced rotation.
- **Password History Bypass**: With PASS_MIN_DAYS=0, users can rapidly change passwords to exhaust the password history and reuse old passwords.
- **Compliance Violations**: Most security frameworks (CIS, NIST, DISA STIG) require password aging policies.

## What Needs to Be Fixed
1. Set `PASS_MAX_DAYS` to 90 (or per organizational policy, typically 60-90 days).
2. Set `PASS_MIN_DAYS` to 10 (or per organizational policy, typically 7-10 days).
3. Set `PASS_WARN_AGE` to 7 (or per organizational policy, typically 7-14 days).
4. Ensure existing users can still change their passwords after remediation.

## Affected Files
- `/etc/login.defs` -- system-wide password aging configuration

## Source Reference
- TAMU `login_defs.sh` -- sets PASS_MAX_DAYS=90, PASS_MIN_DAYS=10, PASS_WARN_AGE=7
- UTSA `script.sh` -- enforces password aging policies
