# Hivestorm HS23 — Ubuntu 20.04 + nginx + (mock) phpbb + multi-vector
# persistence (ruby systemd unit + cron + named-process socat).
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 09 --seed $RANDOM \
#       --out hivestorm/scenario-09-ubuntu-nginx-phpbb/build/roles.json \
#       --render-task hivestorm/scenario-09-ubuntu-nginx-phpbb/task.md
#   docker build hivestorm/scenario-09-ubuntu-nginx-phpbb
#
# mysql is not installed (heavy + needs daemon-init); /etc/mysql/my.cnf is
# planted as a config artifact and scoring is file-state. Same pattern S08
# uses for PHP.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx openssh-server openssh-client sshpass pamtester \
        sudo ufw jq libpam-pwquality cron rsyslog curl \
        coreutils procps iproute2 ca-certificates \
        aircrack-ng nmap hydra \
    && rm -rf /var/lib/apt/lists/*

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh          /etc/sysrepair/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
    && chmod 0700 /etc/sysrepair/seed.sh \
    && /etc/sysrepair/seed.sh \
    && rm /etc/sysrepair/seed.sh

EXPOSE 80 22

# Supervisor starts sshd/cron/nginx so behavioural probes (ssh login, cron
# spawn, HTTP) all exercise live subsystems at submit time.
CMD ["/usr/local/sbin/hs-start.sh"]
