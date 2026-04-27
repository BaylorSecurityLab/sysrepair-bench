FROM --platform=linux/amd64 debian:bookworm-slim

# Modbus/TCP server listening on 0.0.0.0:502 with no authentication.
# Any client can read or write PLC holding registers — a protocol design flaw.
# Remediation: iptables allow-list for port 502 or bind to 127.0.0.1.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        iptables iproute2 netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir pyModbusTCP

COPY modbus_server.py /opt/modbus_server.py

EXPOSE 502

CMD ["/opt/venv/bin/python3", "/opt/modbus_server.py"]
