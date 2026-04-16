# Hivestorm HS23 — Ubuntu 22.04 + faillock + yescrypt + group hygiene.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 10 --seed $RANDOM \
#       --out hivestorm/scenario-10-ubuntu-faillock/build/roles.json \
#       --render-task hivestorm/scenario-10-ubuntu-faillock/task.md
#   docker build hivestorm/scenario-10-ubuntu-faillock
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo ufw jq libpam-modules libpam-pwquality \
        coreutils procps iproute2 ca-certificates \
        nmap aircrack-ng hydra \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh          /etc/sysrepair/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
    && chmod 0700 /etc/sysrepair/seed.sh \
    && /etc/sysrepair/seed.sh \
    && rm /etc/sysrepair/seed.sh

EXPOSE 22

# sshd in foreground so :22 probe works.
CMD ["/usr/sbin/sshd", "-D", "-e"]
