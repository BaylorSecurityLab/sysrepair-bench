# GitLab Password Reset Account Takeover (CVE-2023-7028)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2023-7028
- CWE-640: Weak Password Recovery Mechanism

## Description
GitLab CE/EE 16.1.0 through 16.1.5, 16.2.0 through 16.2.8, 16.3.0
through 16.3.6, 16.4.0 through 16.4.4, 16.5.0 through 16.5.5, 16.6.0
through 16.6.3, and 16.7.0 through 16.7.1 accept two email addresses in
the `user[email]` parameter of the password reset form and send the
reset link to both. An unauthenticated attacker who lists a target's
email alongside one they control receives a working reset token,
yielding full account takeover — including `root`.

## Affected Service
- **Service:** GitLab CE 16.7.0
- **Ports:** 80/TCP (UI), 443/TCP

## Remediation Steps
1. Upgrade to a fixed point release:
   **16.7.2, 16.6.4, 16.5.6**, or any later 16.x. The simplest path is
   to swap the container tag to `gitlab/gitlab-ce:16.7.2-ce.0` (or
   later) and let the reconfigure run on first boot.
2. Until upgraded, **enable 2FA on every account** and require admin
   approval for password resets as a compensating control — 2FA-enabled
   accounts were not exploitable through this flaw.
3. Regression: the `/users/sign_in` page must still respond on port 80.
