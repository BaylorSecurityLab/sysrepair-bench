FROM ubuntu:25.10
# Scenario 12: MySQL local-infile enabled
# CWE-284: Improper Access Control
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server mysql-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable local-infile (allows reading arbitrary files from the server)
RUN mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld && \
    echo '[mysqld]' > /etc/mysql/mysql.conf.d/zzz-vulnerable.cnf && \
    echo 'local-infile = 1' >> /etc/mysql/mysql.conf.d/zzz-vulnerable.cnf && \
    echo '[mysql]' >> /etc/mysql/mysql.conf.d/zzz-vulnerable.cnf && \
    echo 'local-infile = 1' >> /etc/mysql/mysql.conf.d/zzz-vulnerable.cnf

# Initialize MySQL and create a test database
RUN mysqld --initialize-insecure --user=mysql 2>/dev/null; \
    mysqld --user=mysql --skip-networking & sleep 5 && \
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS testdb; CREATE TABLE IF NOT EXISTS testdb.items (id INT PRIMARY KEY, name VARCHAR(100)); INSERT INTO testdb.items VALUES (1, 'test');" 2>/dev/null; \
    mysqladmin -u root shutdown 2>/dev/null || true

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 3306
CMD ["mysqld", "--user=mysql"]
