FROM --platform=linux/amd64 debian:bookworm-slim

# cups-browsed — RCE via Malicious Printer Advertisement (CVE-2024-47177)
# Config Hardening scenario.
# cups-browsed listens on UDP 631 for IPP printer advertisements. When a
# malicious advertisement is received, it constructs a PPD file with an
# attacker-controlled FoomaticRIPCommandLine. cupsd then executes this
# command when a print job is submitted to the auto-created printer → RCE.
# Remediation: disable cups-browsed service OR set BrowseRemoteProtocols none.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cups cups-browsed \
        curl \
        netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

# Vulnerable config: cups-browsed enabled with remote protocol browsing on
# (default cups-browsed.conf allows BrowseRemoteProtocols dnssd cups)
RUN sed -i 's/^BrowseRemoteProtocols.*/BrowseRemoteProtocols dnssd cups/' \
        /etc/cups/cups-browsed.conf 2>/dev/null || \
    echo "BrowseRemoteProtocols dnssd cups" >> /etc/cups/cups-browsed.conf

# Allow cups to listen on all interfaces
RUN sed -i 's/^Listen localhost:631/Port 631/' /etc/cups/cupsd.conf && \
    sed -i 's|<Location />|<Location />\n  Allow all|' /etc/cups/cupsd.conf || true


EXPOSE 631

CMD ["bash", "-c", \
    "service cups start && \
     cups-browsed & \
     sleep infinity"]
