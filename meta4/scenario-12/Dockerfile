FROM --platform=linux/amd64 debian:bookworm-slim

# Simulated Confluence Widget Connector Velocity SSTI (CVE-2019-3396 /
# CWE-1336 / CVSS 9.8). Real Confluence only boots into an un-configured setup
# wizard inside the harness, so a Python/Flask app on port 8090 faithfully
# reproduces the template-injection behaviour: an unauthenticated POST to
# /rest/tinymce/1/macro/preview whose `_template` is a traversal path or an
# embedded directive is evaluated server-side, giving arbitrary file read / RCE.
# This is a DISTINCT CVE/endpoint from scenario-113 (CVE-2022-26134 OGNL-in-URI).
# Remediation: validate `_template` against a safe allowlist, then restart.

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
