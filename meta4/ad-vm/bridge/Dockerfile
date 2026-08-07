# Agent bridge for the meta4/ad-vm suite.
#
# The agent does NOT work in this container. It works on attacker01
# (10.20.30.10), a Linux admin workstation inside the AD lab where
# Invoke-ScenarioInject stages threat.md and creds.txt. This image is only the
# jump box: it holds the SSH client and the throwaway key, and reaches the lab
# through a host portproxy (host.docker.internal:2226 -> 10.20.30.10:22),
# because the lab sits on an INTERNAL Hyper-V switch that a container cannot
# route to directly. Same contract hs13 uses on 2223.
#
# ONE image serves all 20 scenarios: the per-scenario key is bind-mounted at
# run time rather than baked in, so nothing scenario-specific lives here and
# there are no 20 near-identical Dockerfiles to drift apart.
#
# Deliberately NOT included: certipy, impacket, nxc and the rest of the AD
# offensive toolkit. Those live in srb-attacker:1 on the attacker VM and are
# the GRADER's instruments, not the agent's. An agent that could run the PoC
# locally could also discover exactly what is graded.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-client \
      ca-certificates \
      iputils-ping \
      netcat-openbsd \
      dnsutils \
      less \
      vim-tiny \
      procps \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# ssh(1) refuses a private key whose mode is too open, and a bind mount from a
# Windows host presents as 0777. The key is therefore mounted read-only at
# /srb/bridge_key.ro and copied into place with 0600 by the container command
# (see task.py), not COPYed here.
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Host key checking is disabled for the lab target only: the VM is rebuilt from
# a checkpoint for every scenario, so its host key legitimately changes and a
# known_hosts mismatch would look to the agent like a broken environment.
RUN printf 'Host lab\n\
    HostName host.docker.internal\n\
    Port 2226\n\
    User vagrant\n\
    IdentityFile /root/.ssh/id_ed25519\n\
    StrictHostKeyChecking no\n\
    UserKnownHostsFile /dev/null\n\
    LogLevel ERROR\n' > /root/.ssh/config \
 && chmod 600 /root/.ssh/config

WORKDIR /root
