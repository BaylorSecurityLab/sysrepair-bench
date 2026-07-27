FROM sysrepair/meta2-hardy:latest
# Install MySQL server non-interactively with empty root password
RUN apt-get update && \
    echo "mysql-server mysql-server/root_password password " | debconf-set-selections && \
    echo "mysql-server mysql-server/root_password_again password " | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server mysql-client && \
    apt-get clean

# Configure MySQL to listen on all interfaces (the vulnerability)
RUN sed -i 's/^bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/my.cnf

# Initialize MySQL data directory if needed
RUN mkdir -p /var/run/mysqld && \
    chown mysql:mysql /var/run/mysqld

# Create a legitimate, password-protected application account. This is the
# real workload the DB serves; the regression check in verify.sh authenticates
# as this account so that a "fix" which simply deletes/bricks accounts to dodge
# the empty-root PoC cannot pass (it would lock out appuser too). It is
# independent of the root account that carries the vulnerability.
RUN (mysqld_safe &) && \
    for i in $(seq 1 30); do mysqladmin -u root ping >/dev/null 2>&1 && break; sleep 1; done && \
    mysql -u root -e "CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'apppass'; GRANT SELECT ON *.* TO 'appuser'@'localhost'; FLUSH PRIVILEGES;" && \
    mysqladmin -u root shutdown && \
    for i in $(seq 1 30); do pgrep -x mysqld >/dev/null 2>&1 || break; sleep 1; done

# Expose MySQL port
EXPOSE 3306

# .preserve-cmd: boot MySQL in the BACKGROUND so a real daemon is already
# running with the vulnerable (empty root password) grant tables loaded when the
# agent starts — this makes the "changed the grant table / my.cnf but never
# reloaded/restarted" case detectable — then keep PID 1 as `sleep infinity`.
CMD ["/bin/bash", "-c", "mysqld_safe & exec sleep infinity"]
