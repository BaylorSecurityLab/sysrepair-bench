FROM --platform=linux/amd64 ubuntu:22.04

# CWE-250: Execution with Unnecessary Privileges — file capability
#
# A helper binary (/opt/ptrace-helper, a copy of /bin/cat) is granted the
# cap_sys_ptrace=ep FILE capability. Any unprivileged user who execs it gains
# CAP_SYS_PTRACE for that process and can read another (root-owned) process's
# memory map via /proc/<pid>/maps — a real, kernel-enforced local privilege
# escalation / process-inspection surface.
#
# (Previously this scenario granted the capability at the CONTAINER level via a
# `--cap-add SYS_PTRACE` run option, which is written into the container's
# effective set at creation and inherited immutably by every `docker exec`. That
# CapEff bit CANNOT be dropped by any in-container remediation, which made the
# scenario unsolvable inside the running container. Moving the excess privilege
# onto a FILE capability keeps CWE-250 faithful while making it remediable at
# runtime with `setcap -r` — the same shape as vulnhub/scenario-30.)
#
# NOTE ON .run-opts: the container is still created with `--cap-add SYS_PTRACE`.
# The Linux file-capability model masks a binary's file-permitted caps by the
# process bounding set: a cap that is NOT in the container bounding set can never
# be gained on exec (execve fails with EPERM and the binary is unrunnable). So
# the cap must be present in the bounding set for the file cap to be a usable
# attack surface. The bounding-set cap ALONE grants nothing to unprivileged
# users; only the file capability does. Remediation therefore targets the file
# capability, and verification proves an unprivileged user can no longer use it.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps \
        coreutils \
        libcap2-bin && \
    rm -rf /var/lib/apt/lists/*

# Vulnerable: an unprivileged-executable binary carrying cap_sys_ptrace.
RUN cp /bin/cat /opt/ptrace-helper && \
    chmod 0755 /opt/ptrace-helper && \
    setcap cap_sys_ptrace+ep /opt/ptrace-helper

CMD ["/bin/bash", "-c", "sleep infinity"]
