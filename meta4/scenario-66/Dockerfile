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

EXPOSE 623/udp

# Boot wrapper (see .preserve-cmd): start the IPMI BMC simulator in the
# BACKGROUND then exec `sleep infinity` so PID 1 is the wrapper, keeping the
# vulnerable service listening while a solution's firewall rules cannot kill it.
CMD ["/bin/bash", "-c", "python3 /opt/ipmi_server.py & exec sleep infinity"]
