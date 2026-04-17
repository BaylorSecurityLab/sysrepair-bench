FROM --platform=linux/amd64 debian:bullseye-slim

# SaltStack 3000 — ClearFuncs Auth Bypass (CVE-2020-11651) — Compensating Controls
# The salt-master ZeroMQ publisher (4505) and return bus (4506) lack authentication
# on the ClearFuncs class, allowing unauthenticated callers to execute arbitrary
# Salt runner/wheel functions → RCE on all connected minions.
# Remediation (NOT upgrade): iptables restrict ports 4505/4506 to trusted minion
# IPs; configure publisher_acl in master config.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg iptables \
        python3 python3-pip python3-setuptools \
        python3-dev gcc make autoconf && \
    rm -rf /var/lib/apt/lists/*

# Install SaltStack 3000 (vulnerable version via pip)
RUN pip3 install distro && pip3 install "salt==3000"

# Vulnerable master config: no publisher_acl, ports open to all
RUN mkdir -p /etc/salt && cat > /etc/salt/master <<'EOF'
# SaltStack master config — VULNERABLE (no publisher_acl, no ACL)
interface: 0.0.0.0
publish_port: 4505
ret_port: 4506
# No publisher_acl configured — any caller can invoke ClearFuncs
EOF

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 4505 4506

CMD ["bash", "-c", "salt-master -d && sleep infinity"]
