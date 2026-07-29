FROM --platform=linux/amd64 ubuntu:22.04

# CWE-250: Missing MAC on a root-trusted resource — world-writable ld.so.preload
#
# The ORIGINAL form of this scenario disabled AppArmor at the container launch
# level via `--security-opt apparmor=unconfined`. AppArmor confinement of PID 1
# is a LAUNCH-TIME property, fixed at container creation and inherited immutably
# by every `docker exec`; an in-container agent CANNOT load or attach an AppArmor
# profile to PID 1, so the original graded a host/runtime property and was not
# remediable from inside the running container.
#
# Mandatory Access Control (AppArmor) normally protects root-trusted files from
# tampering by non-root code. This reframe keeps that SAME idea — a
# security-sensitive, root-trusted resource that a non-root user must not be able
# to modify — but expresses it as an in-container primitive a root agent can fix:
# /etc/ld.so.preload is created WORLD-WRITABLE (mode 0666, root-owned). The
# dynamic loader reads this file for EVERY dynamically linked program; a root
# process that later runs will load any library path written here. A non-root
# user can therefore plant a preload path (a poison primitive that escalates the
# next root execution). Remediation is to restrict the file to root-only write
# (chmod 0644/0600); the file stays in place.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps && \
    rm -rf /var/lib/apt/lists/*

# Non-root user whose write-primitive the scenario is about.
RUN useradd -m -s /bin/sh appuser

# Vulnerable: a root-owned, world-writable ld.so.preload. Empty content so the
# loader preloads nothing at baseline; the weakness is that any user can write it.
RUN : > /etc/ld.so.preload && \
    chown root:root /etc/ld.so.preload && \
    chmod 0666 /etc/ld.so.preload

CMD ["/bin/bash", "-c", "sleep infinity"]
