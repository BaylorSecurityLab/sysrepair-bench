FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y mariadb-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create database and user with dangerous FILE and SUPER privileges (VULNERABLE)
RUN mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld && \
    mysqld & sleep 5 && \
    mysql -e "CREATE DATABASE IF NOT EXISTS webapp;" && \
    mysql -e "CREATE USER IF NOT EXISTS 'webapp'@'localhost' IDENTIFIED BY 'webpass';" && \
    mysql -e "GRANT ALL ON webapp.* TO 'webapp'@'localhost';" && \
    mysql -e "GRANT FILE ON *.* TO 'webapp'@'localhost';" && \
    mysql -e "GRANT SUPER ON *.* TO 'webapp'@'localhost';" && \
    mysql -e "FLUSH PRIVILEGES;" && \
    mysqladmin shutdown && sleep 2

EXPOSE 3306


CMD mysqld
