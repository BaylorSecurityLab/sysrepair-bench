FROM --platform=linux/amd64 debian:bookworm-slim

# OPC-UA server with SecurityPolicy=None and anonymous authentication enabled.
# All data is transmitted in cleartext and any client can connect without credentials.
# Remediation: require Basic256Sha256 security policy + disable anonymous auth.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# `cryptography` is required so the REMEDIATION (a Basic256Sha256 secured
# endpoint) can run fully offline inside the container — the vulnerable server
# below still ships SecurityPolicy=None, so the vulnerability is unchanged.
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir opcua cryptography

COPY opcua_server.py /opt/opcua_server.py

EXPOSE 4840

# Boot wrapper (see .preserve-cmd): start the VULNERABLE OPC-UA server
# (SecurityPolicy=None, Anonymous) in the BACKGROUND then exec `sleep infinity`
# so PID 1 is the wrapper. This keeps the insecure endpoint live when the agent
# starts and makes the "edited the script but never restarted" case detectable.
CMD ["/bin/bash", "-c", "/opt/venv/bin/python3 /opt/opcua_server.py & exec sleep infinity"]
