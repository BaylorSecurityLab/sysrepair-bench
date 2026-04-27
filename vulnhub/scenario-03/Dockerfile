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

CMD ["mysqld_safe"]
