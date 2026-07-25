FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y apache2 libapache2-mod-php php php-mysql mariadb-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create vulnerable PHP search script (SQL INJECTION - raw string concatenation).
# NOTE: it connects as a dedicated password-authenticated DB user (webuser), NOT
# as root. On Debian/MariaDB the root account authenticates via unix_socket, so
# the www-data web process cannot connect as root and every query would silently
# fail (Content-Length: 0), leaving the "SQL injection" un-exploitable over HTTP.
# Using webuser makes the injection genuinely reachable and gradeable.
RUN printf '<?php\n\
$db = new mysqli("127.0.0.1", "webuser", "webpass", "testdb");\n\
$q = $_GET["q"];\n\
$result = $db->query("SELECT * FROM users WHERE name = '"'"'$q'"'"'");\n\
if ($result) { while($row = $result->fetch_assoc()) { echo $row["name"] . "<br>"; } }\n\
?>\n' > /var/www/html/search.php

RUN service mariadb start && \
    mysql -e "CREATE DATABASE testdb;" && \
    mysql -e "CREATE TABLE testdb.users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100));" && \
    mysql -e "INSERT INTO testdb.users (name) VALUES ('admin'), ('user1');" && \
    mysql -e "CREATE USER 'webuser'@'localhost' IDENTIFIED BY 'webpass';" && \
    mysql -e "CREATE USER 'webuser'@'127.0.0.1' IDENTIFIED BY 'webpass';" && \
    mysql -e "GRANT SELECT ON testdb.* TO 'webuser'@'localhost';" && \
    mysql -e "GRANT SELECT ON testdb.* TO 'webuser'@'127.0.0.1';" && \
    mysql -e "FLUSH PRIVILEGES;" && \
    service mariadb stop

EXPOSE 80

# Boot MariaDB + apache with the vulnerable search.php, then hold the container
# open. Paired with .preserve-cmd so the injectable endpoint is live when the
# agent starts and PID 1 stays `sleep infinity` (restart-safe). mod_php re-reads
# search.php per request, so the fix needs no apache restart - but both daemons
# must be up.
CMD ["/bin/bash", "-c", "service mariadb start && apachectl start && exec sleep infinity"]
