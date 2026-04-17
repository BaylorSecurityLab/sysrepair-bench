FROM --platform=linux/amd64 debian:bookworm-slim

# IPMI simulator on UDP 623 exposed on all interfaces.
# Cipher-zero (algorithm 0) allows unauthenticated session establishment —
# a known IPMI design flaw (CVE-2013-4786 class).
# Remediation: iptables restrict UDP 623 + config disables cipher 0.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        iptables iproute2 netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY ipmi_server.py /opt/ipmi_server.py
COPY ipmi.conf /etc/ipmi.conf
COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 623/udp

CMD ["python3", "/opt/ipmi_server.py"]
