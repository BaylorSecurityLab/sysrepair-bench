FROM --platform=linux/amd64 ubuntu:22.04

# CVE-2022-0492 / CWE-250: Execution with Unnecessary Privileges — file capability
#
# CVE-2022-0492 abuses CAP_SYS_ADMIN inside a container (cgroup-v1
# notify_on_release / release_agent) to escape to the host. The ORIGINAL form of
# this scenario granted CAP_SYS_ADMIN at the CONTAINER level via
# `--security-opt seccomp=unconfined --security-opt apparmor=unconfined` — a
# launch-time property written into PID 1's capability/confinement state at
# creation and inherited immutably by every `docker exec`. An in-container agent
# CANNOT drop it, which made the scenario unsolvable inside the running container.
#
# This reframe keeps the SAME weakness (an unprivileged user wielding
# CAP_SYS_ADMIN) but relocates it onto a FILE capability on a helper binary:
# /usr/local/bin/caphelper carries cap_sys_admin+ep and is world-executable. Any
# unprivileged user who execs it gains CAP_SYS_ADMIN and can perform a privileged
# mount (the same capability CVE-2022-0492 turns into a host escape). This is
# remediable at runtime with `setcap -r`, mirroring meta4/scenario-69 and
# meta4/scenario-74.
#
# NOTE ON .run-opts: the container is created with `--cap-add SYS_ADMIN`. The
# Linux file-capability model masks a binary's file-permitted caps by the process
# bounding set: a cap absent from the bounding set can never be gained on exec
# (execve raises nothing and the privileged op fails). So the cap must be in the
# bounding set for the file capability to be a usable surface. The bounding-set
# cap ALONE grants nothing to unprivileged users; only the file capability does.
# Remediation targets the file capability.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps \
        coreutils \
        libcap2-bin \
        gcc \
        libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Non-root user whose escalation the scenario is about.
RUN useradd -m -s /bin/sh appuser

# Vulnerable: compile a tiny CAP_SYS_ADMIN-gated helper, grant it the file
# capability world-executable, then purge the toolchain so no compiler remains.
COPY caphelper.c /tmp/caphelper.c
RUN gcc -O2 -o /usr/local/bin/caphelper /tmp/caphelper.c && \
    rm -f /tmp/caphelper.c && \
    chown root:root /usr/local/bin/caphelper && \
    chmod 0755 /usr/local/bin/caphelper && \
    setcap cap_sys_admin+ep /usr/local/bin/caphelper && \
    apt-get purge -y gcc libc6-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash", "-c", "sleep infinity"]
