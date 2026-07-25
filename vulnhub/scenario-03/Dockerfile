FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y mariadb-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure MySQL with NO secure_file_priv (VULNERABLE)
RUN echo "[mysqld]\nsecure_file_priv=" >> /etc/mysql/mariadb.conf.d/99-vulnerable.cnf

RUN service mariadb start && \
    mysql -e "CREATE DATABASE webapp;" && \
    mysql -e "CREATE USER 'webuser'@'localhost' IDENTIFIED BY 'webpass';" && \
    mysql -e "GRANT ALL ON webapp.* TO 'webuser'@'localhost';" && \
    mysql -e "GRANT FILE ON *.* TO 'webuser'@'localhost';" && \
    service mariadb stop

EXPOSE 3306

# Boot MariaDB (with secure_file_priv unset) in the background, wait for the
# socket, then hold the container open. Paired with .preserve-cmd so:
#   1. the DB is ALREADY running with the unrestricted config when the agent
#      starts - secure_file_priv is a start-up-only variable, so a config edit
#      that never restarts mariadb still fails verify.sh;
#   2. PID 1 is `sleep infinity`, not mysqld, so restarting the DB cannot kill
#      the container.
CMD ["/bin/bash", "-c", "mysqld_safe & for i in $(seq 1 60); do [ -S /run/mysqld/mysqld.sock ] && break; sleep 0.5; done; exec sleep infinity"]
