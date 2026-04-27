FROM --platform=linux/amd64 debian:bookworm-slim

# OPC-UA server with SecurityPolicy=None and anonymous authentication enabled.
# All data is transmitted in cleartext and any client can connect without credentials.
# Remediation: require Basic256Sha256 security policy + disable anonymous auth.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir opcua

COPY opcua_server.py /opt/opcua_server.py

EXPOSE 4840

CMD ["/opt/venv/bin/python3", "/opt/opcua_server.py"]
