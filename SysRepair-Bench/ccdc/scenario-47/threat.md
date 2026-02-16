# Scenario 47: No PAM Password Complexity (pwquality)

## Vulnerability
The PAM password quality module (`pam_pwquality`) has been configured with extremely permissive settings in `/etc/security/pwquality.conf`:
- `minlen = 1` -- minimum password length of just 1 character
- `dcredit = 0`, `ucredit = 0`, `lcredit = 0`, `ocredit = 0` -- no character class requirements
- `minclass = 0` -- no minimum number of character classes
- `dictcheck = 0` -- dictionary check disabled
- `enforcing = 0` -- quality checks not enforced

This allows users to set trivially weak passwords like "a", "1", or common dictionary words, making accounts highly vulnerable to brute-force and dictionary attacks.

## CWE Classification
- **CWE-521**: Weak Password Requirements

## Impact
- **Weak Passwords**: Users can set single-character or dictionary-word passwords.
- **Brute-Force Vulnerability**: Accounts with weak passwords can be compromised in seconds.
- **Compliance Violations**: Fails to meet CIS, NIST 800-53, and DISA STIG password requirements.

## What Needs to Be Fixed
1. Set `minlen` to at least 14 (or per organizational policy).
2. Configure credit values to require character diversity: `dcredit = -1`, `ucredit = -1`, `lcredit = -1`, `ocredit = -1`.
3. Set `minclass = 4` to require at least 4 character classes.
4. Enable `dictcheck = 1` for dictionary checking.
5. Set `enforcing = 1` to enforce the quality requirements.
6. Set `maxrepeat = 3` and `maxclassrepeat = 4` to limit repetition.
7. Ensure users can still change their passwords after applying the new policy.

## Affected Files
- `/etc/security/pwquality.conf` -- password quality configuration

## Source Reference
- UTSA `script.sh` -- comprehensive pwquality settings enforcement
