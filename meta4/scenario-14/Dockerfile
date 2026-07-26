FROM --platform=linux/amd64 debian:bookworm-slim

# Simulated GitLab password-reset account takeover (CVE-2023-7028 / CWE-640 /
# CVSS 10.0). A full GitLab omnibus upgrade far exceeds the harness timeouts, so
# a Python/Flask app on port 80 faithfully reproduces the takeover primitive:
# the reset form accepts an array of recipient addresses and delivers the reset
# token to ALL of them, letting an attacker receive a victim's token and change
# the victim's password (real state change). Remediation: reject array
# recipients in the reset handler, then restart.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-flask \
        curl \
        && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/gitlab
COPY app.py /opt/gitlab/app.py

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 80

CMD ["/opt/start.sh"]
