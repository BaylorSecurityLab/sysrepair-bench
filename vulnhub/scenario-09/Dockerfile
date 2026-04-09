FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php && apt-get clean && rm -rf /var/lib/apt/lists/*
# VULNERABLE command execution script
RUN printf '<?php\nif(isset($_POST["cmd"])) {\n    $output = system($_POST["cmd"]);\n    echo "<pre>$output</pre>";\n}\n?>\n<form method="POST"><input name="cmd"><button>Run</button></form>' > /var/www/html/cmd.php
EXPOSE 80
COPY verify.sh /verify.sh
CMD ["apachectl", "-D", "FOREGROUND"]
