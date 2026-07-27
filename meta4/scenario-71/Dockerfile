FROM --platform=linux/amd64 ubuntu:22.04

# CWE-250: Execution with Unnecessary Privileges — SUID-root helper
#
# The ORIGINAL form of this scenario disabled seccomp at the container launch
# level via `--security-opt seccomp=unconfined`. Seccomp confinement of PID 1 is
# a LAUNCH-TIME property, fixed at container creation and inherited immutably by
# every `docker exec`; an in-container agent CANNOT re-enable a seccomp filter on
# PID 1, so the original graded a host/runtime property and was not remediable
# from inside the running container.
#
# This reframe keeps the SAME CWE-250 weakness — an unnecessary, dangerous
# execution privilege that lets a non-root user gain root — but expresses it as
# an in-container primitive a root agent genuinely CAN fix: a SUID-root helper
# binary. /usr/local/bin/suidhelper is owned by root with the setuid bit set, so
# any unprivileged user who runs it becomes root. Remediation is `chmod u-s`
# (strip the SUID bit); the binary stays in place.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps \
        gcc \
        libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Non-root user whose escalation the scenario is about.
RUN useradd -m -s /bin/sh appuser

# Vulnerable: compile a tiny setuid(0) helper, make it SUID-root world-executable,
# then purge the toolchain so no compiler remains.
COPY suidhelper.c /tmp/suidhelper.c
RUN gcc -O2 -o /usr/local/bin/suidhelper /tmp/suidhelper.c && \
    rm -f /tmp/suidhelper.c && \
    chown root:root /usr/local/bin/suidhelper && \
    chmod 4755 /usr/local/bin/suidhelper && \
    apt-get purge -y gcc libc6-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash", "-c", "sleep infinity"]
