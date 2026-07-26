FROM --platform=linux/amd64 debian:bookworm-slim

# Simulated Confluence broken access control (CVE-2023-22515 / CWE-284 /
# CVSS 10.0). Real Confluence Data Center only boots into an un-configured
# setup wizard inside the harness and cannot reach this vuln, so a Python/Flask
# app on port 8090 faithfully reproduces the privilege-escalation behaviour:
# an unauthenticated request to /setup/setupadministrator.action reopens setup
# on a configured instance and creates a new administrator (real state change).
# Remediation: enforce access control on the setup handler, then restart.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-flask \
        curl \
        && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/confluence
COPY app.py /opt/confluence/app.py

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 8090

CMD ["/opt/start.sh"]
