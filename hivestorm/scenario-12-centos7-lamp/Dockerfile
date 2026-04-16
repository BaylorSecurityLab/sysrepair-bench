# Hivestorm scenario-12 — CentOS 7 / RHEL-family LAMP free-roam.
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 12 --seed $RANDOM \
#     --out hivestorm/scenario-12-centos7-lamp/build/roles.json \
#     --render-task hivestorm/scenario-12-centos7-lamp/task.md
#   docker build hivestorm/scenario-12-centos7-lamp
#
# CentOS 7 is EOL; seed.sh rewrites yum repos to vault.centos.org before any
# yum operation. Container does not run systemd — the supervisor script starts
# sshd, httpd, and mariadb directly. firewalld/selinux are represented as
# config-file state (no kernel enforcement inside the container).

FROM centos:7

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh /usr/local/sbin/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
 && chmod 0755 /usr/local/sbin/seed.sh \
 && /usr/local/sbin/seed.sh \
 && rm -f /usr/local/sbin/seed.sh

EXPOSE 22 80 3306

CMD ["/usr/local/sbin/hs-start.sh"]
