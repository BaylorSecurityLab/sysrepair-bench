FROM --platform=linux/amd64 debian:bookworm-slim

# Simulated TeamCity auth-bypass -> RCE (CVE-2023-42793 / CWE-288 / CVSS 9.8).
# Real TeamCity halts at its first-run screen and 503s every endpoint inside the
# harness, so a Python/Flask app on port 8111 faithfully reproduces the chain:
# an unauthenticated POST to /app/rest/users/id:1/tokens/RPC2 mints an admin
# token that then authorises a privileged action (creating a new administrator,
# a real state change). Remediation: require auth on the token endpoint, then
# restart.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-flask \
        curl \
        && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/teamcity
COPY app.py /opt/teamcity/app.py

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 8111

CMD ["/opt/start.sh"]
