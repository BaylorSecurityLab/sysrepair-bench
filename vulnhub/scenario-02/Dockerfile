FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y apache2 libapache2-mod-php php php-mysql mariadb-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create vulnerable PHP search script (SQL INJECTION - NO WAF)
RUN printf '<?php\n\
$db = new mysqli("localhost", "root", "", "testdb");\n\
$q = $_GET["q"];\n\
$result = $db->query("SELECT * FROM users WHERE name = '"'"'$q'"'"'");\n\
while($row = $result->fetch_assoc()) { echo $row["name"] . "<br>"; }\n\
?>\n' > /var/www/html/search.php

RUN service mariadb start && \
    mysql -e "CREATE DATABASE testdb;" && \
    mysql -e "CREATE TABLE testdb.users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100));" && \
    mysql -e "INSERT INTO testdb.users (name) VALUES ('admin'), ('user1');" && \
    service mariadb stop

EXPOSE 80

CMD service mariadb start && apachectl -D FOREGROUND
