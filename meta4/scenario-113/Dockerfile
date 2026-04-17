FROM --platform=linux/amd64 debian:bookworm-slim

# Simulated Confluence OGNL Injection (CVE-2022-26134 / CWE-917 / CVSS 9.8).
# Real Confluence is too heavy; a Python/Flask app simulates the vulnerable
# endpoint on port 8090. No nginx WAF present — vulnerable state.
# Remediation (compensating control): nginx reverse proxy blocking OGNL
# expressions in URIs. Confluence version is NOT upgraded.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-flask \
        curl \
        iproute2 \
        iptables \
        nginx \
        && \
    rm -rf /var/lib/apt/lists/*

# Simulated Confluence app
RUN mkdir -p /opt/confluence
COPY app.py /opt/confluence/app.py

# Startup script
COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80 8090

CMD ["/opt/start.sh"]
