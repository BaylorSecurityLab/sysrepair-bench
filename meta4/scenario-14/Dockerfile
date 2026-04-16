FROM --platform=linux/amd64 gitlab/gitlab-ce:16.7.0-ce.0

# GitLab CE 16.7.0 — password-reset email sent to unverified secondary
# address (CVE-2023-7028). An attacker submits a password reset request
# with two email addresses; GitLab sends the reset link to BOTH, so the
# attacker receives a working reset token for any user — including
# `root` — without prior authentication or interaction. Over 5,300
# internet-exposed instances were vulnerable at disclosure.

EXPOSE 80 443
