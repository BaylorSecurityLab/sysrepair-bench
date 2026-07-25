FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php php-mysql mariadb-server && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN service mariadb start && \
    mysql -e "CREATE DATABASE wordpress;" && \
    mysql -e "CREATE TABLE wordpress.wp_users (ID INT PRIMARY KEY, user_login VARCHAR(60), user_pass VARCHAR(255), user_email VARCHAR(100));" && \
    mysql -e "INSERT INTO wordpress.wp_users VALUES (1, 'admin', '\$P\$BhWEqSH2qDK3BNeQSa12wD3G7Z1wp4/', 'admin@local.host');" && \
    mysql -e "INSERT INTO wordpress.wp_users VALUES (2, 'editor', '\$P\$BVXxf.YpxRwQY6miGkfRdkjox3v3N7/', 'editor@local.host');" && \
    service mariadb stop
EXPOSE 80
# Boot MariaDB (holding the weak wp_users hashes) + apache, then hold the
# container open. Paired with .preserve-cmd so the DB is live for verify.sh to
# query and PID 1 stays `sleep infinity`. (The hashes are data read per query,
# so the fix needs no restart - but the DB must be up.)
CMD ["/bin/bash", "-c", "service mariadb start && apachectl start && exec sleep infinity"]
