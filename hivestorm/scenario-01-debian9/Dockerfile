# Hivestorm HS20 — Debian 9 LAMP+SSH free-roam scenario.
#
# Build contract:
#   1. Generate roles.json:
#        python -m hivestorm.common.roles \
#            --scenario 01 --seed $RANDOM \
#            --out hivestorm/scenario-01-debian9/build/roles.json \
#            --render-task hivestorm/scenario-01-debian9/task.md
#   2. docker build hivestorm/scenario-01-debian9
#
# Debian 9 is EOL; repos live on archive.debian.org. seed.sh rewrites
# sources.list before any apt-get.

FROM debian:9

ARG DEBIAN_FRONTEND=noninteractive

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh /usr/local/sbin/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
 && chmod 0755 /usr/local/sbin/seed.sh \
 && /usr/local/sbin/seed.sh \
 && rm -f /usr/local/sbin/seed.sh

EXPOSE 22 80 3306

# Run sshd + apache + mysql via a tiny supervisor script dropped by seed.sh.
CMD ["/usr/local/sbin/hs-start.sh"]
