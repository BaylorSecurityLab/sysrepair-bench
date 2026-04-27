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
CMD service mariadb start && apachectl -D FOREGROUND
