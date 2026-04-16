# Hivestorm HS20 — Ubuntu 16.04 free-roam scenario.
#
# Build contract (same as scenario-01):
#   python -m hivestorm.common.roles --scenario 02 --seed $RANDOM \
#       --out hivestorm/scenario-02-ubuntu1604/build/roles.json \
#       --render-task hivestorm/scenario-02-ubuntu1604/task.md
#   docker build hivestorm/scenario-02-ubuntu1604
#
# Ubuntu 16.04 is EOL; repos live on old-releases.ubuntu.com. seed.sh rewrites
# sources.list before any apt-get.

FROM ubuntu:16.04

ARG DEBIAN_FRONTEND=noninteractive

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh /usr/local/sbin/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
 && chmod 0755 /usr/local/sbin/seed.sh \
 && /usr/local/sbin/seed.sh \
 && rm -f /usr/local/sbin/seed.sh

EXPOSE 22 139 445

CMD ["/usr/local/sbin/hs-start.sh"]
