# Hivestorm HS21 — Debian 9 + PostgreSQL free-roam scenario.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 06 --seed $RANDOM \
#       --out hivestorm/scenario-06-debian9-postgres/build/roles.json \
#       --render-task hivestorm/scenario-06-debian9-postgres/task.md
#   docker build hivestorm/scenario-06-debian9-postgres
#
# Debian 9 is EOL; seed.sh rewrites sources.list to archive.debian.org before
# any apt-get.

FROM debian:9

ARG DEBIAN_FRONTEND=noninteractive

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh /usr/local/sbin/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
 && chmod 0755 /usr/local/sbin/seed.sh \
 && /usr/local/sbin/seed.sh \
 && rm -f /usr/local/sbin/seed.sh

EXPOSE 22 5432

CMD ["/usr/local/sbin/hs-start.sh"]
