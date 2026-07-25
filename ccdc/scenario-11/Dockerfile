FROM ubuntu:25.10
# Scenario 11: MySQL remote root login + no bind-address
# CWE-284: Improper Access Control
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server mysql-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure MySQL to listen on all interfaces and allow remote root login
RUN mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld && \
    echo '[mysqld]' > /etc/mysql/mysql.conf.d/zzz-vulnerable.cnf && \
    echo 'bind-address = 0.0.0.0' >> /etc/mysql/mysql.conf.d/zzz-vulnerable.cnf && \
    echo 'skip-grant-tables' >> /etc/mysql/mysql.conf.d/zzz-vulnerable.cnf

# Initialize MySQL and create a test database
RUN mysqld --initialize-insecure --user=mysql 2>/dev/null; \
    mysqld --user=mysql --skip-networking &  sleep 5 && \
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS testdb; CREATE TABLE IF NOT EXISTS testdb.items (id INT PRIMARY KEY, name VARCHAR(100)); INSERT INTO testdb.items VALUES (1, 'test');" 2>/dev/null; \
    mysqladmin -u root shutdown 2>/dev/null || true


EXPOSE 3306

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker so the harness keeps this
# CMD instead of replacing it. mysqld has no daemonizing mode we can rely on
# here, so it is backgrounded with `&` and we wait for it to accept connections
# before handing the box over.
#   1. mysqld must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live daemon vulnerable and verify.sh fails.
#   2. PID 1 must NOT be mysqld - restarting the service would otherwise kill
#      the container. `exec sleep infinity` keeps a stable PID 1.
CMD ["/bin/bash", "-c", "mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld && mysqld --user=mysql >/var/log/mysqld-boot.log 2>&1 & for i in $(seq 1 60); do mysqladmin -u root ping >/dev/null 2>&1 && break; sleep 1; done; exec sleep infinity"]
