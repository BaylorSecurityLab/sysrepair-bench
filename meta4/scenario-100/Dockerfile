FROM --platform=linux/amd64 python:3.7-slim-bullseye

# SaltStack 3000 — ClearFuncs Auth Bypass (CVE-2020-11651) — Compensating Controls
# The salt-master ZeroMQ publisher (4505) and return bus (4506) lack authentication
# on the ClearFuncs class, allowing unauthenticated callers to execute arbitrary
# Salt runner/wheel functions → RCE on all connected minions.
# Remediation (NOT upgrade): iptables restrict ports 4505/4506 to trusted minion
# IPs; configure publisher_acl in master config.
#
# NB: salt==3000 imports platform._supported_dists, which was REMOVED in Python
# 3.8. On a stock bullseye base (Python 3.9) salt-master crashes on import and
# never starts - the vulnerable daemon would not exist. We therefore pin a
# Python 3.7 base so the vulnerable salt-master is genuinely runnable. salt is
# version-pinned to ==3000 (the vulnerable release) for a reproducible build.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg iptables \
        gcc make autoconf libzmq3-dev && \
    rm -rf /var/lib/apt/lists/*

# Install SaltStack 3000 (vulnerable version via pip)
# salt 3000 predates jinja2 3.x (which removed jinja2.Markup) and markupsafe 2.x
# (which removed soft_unicode); pin the era-correct versions so salt-master imports.
#
# Integrity gate: the pip fetch is non-hermetic (live PyPI), so the exact
# artifacts are sha256-pinned. We `pip download --no-deps` the vulnerable salt
# sdist and its era-locked jinja2/markupsafe wheels, verify each with
# `sha256sum -c -` (a substituted/tampered wheel aborts the build here), then
# `pip install` the verified local files. distro is a runtime helper (unpinned).
# Hashes are the observed sha256 of the exact files PyPI serves for python 3.7.
RUN pip install --no-cache-dir distro && \
    mkdir -p /tmp/wheels && \
    pip download --no-deps -d /tmp/wheels \
        "salt==3000" "jinja2==2.11.3" "markupsafe==1.1.1" && \
    ( cd /tmp/wheels && \
      printf '%s  %s\n' \
        04fbc64933b375cbbefc9576bcc65167b74d5eec7f58e64d096d67529ea66500 salt-3000.tar.gz \
        03e47ad063331dd6a3f04a43eddca8a966a26ba0c5b7207a9a9e4e08f1b29419 Jinja2-2.11.3-py2.py3-none-any.whl \
        a6a744282b7718a2a62d2ed9d993cad6f5f585605ad352c11de459f4108df0a1 MarkupSafe-1.1.1-cp37-cp37m-manylinux2010_x86_64.whl \
      | sha256sum -c - ) && \
    pip install --no-cache-dir \
        /tmp/wheels/salt-3000.tar.gz \
        /tmp/wheels/Jinja2-2.11.3-py2.py3-none-any.whl \
        /tmp/wheels/MarkupSafe-1.1.1-cp37-cp37m-manylinux2010_x86_64.whl && \
    rm -rf /tmp/wheels

# Vulnerable master config: no publisher_acl, ports open to all
RUN mkdir -p /etc/salt && cat > /etc/salt/master <<'EOF'
# SaltStack master config — VULNERABLE (no publisher_acl, no ACL)
interface: 0.0.0.0
publish_port: 4505
ret_port: 4506
# No publisher_acl configured — any caller can invoke ClearFuncs
EOF


EXPOSE 4505 4506

# Boot the vulnerable salt-master (daemonised) then hold the container open with
# `exec sleep infinity` so PID 1 is never salt-master. Paired with `.preserve-cmd`
# so the harness keeps this CMD and the daemon is already listening on 4505/4506
# when the agent starts.
CMD ["bash", "-c", "salt-master -d; exec sleep infinity"]
