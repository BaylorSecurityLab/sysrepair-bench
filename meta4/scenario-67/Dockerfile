FROM --platform=linux/amd64 debian:bookworm-slim

# BACnet/IP server on UDP 0.0.0.0:47808 with no authentication.
# Building automation protocol with no native auth — a protocol design flaw.
# Remediation: iptables restrict UDP 47808 to BMS subnet.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        iptables iproute2 netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY bacnet_server.py /opt/bacnet_server.py
COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 47808/udp

CMD ["python3", "/opt/bacnet_server.py"]
