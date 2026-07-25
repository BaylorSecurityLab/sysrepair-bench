FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php && apt-get clean && rm -rf /var/lib/apt/lists/*
# VULNERABLE command execution script
RUN printf '<?php\nif(isset($_POST["cmd"])) {\n    $output = system($_POST["cmd"]);\n    echo "<pre>$output</pre>";\n}\n?>\n<form method="POST"><input name="cmd"><button>Run</button></form>' > /var/www/html/cmd.php
EXPOSE 80
# Boot the vulnerable apache serving cmd.php then hold the container open.
# Paired with .preserve-cmd so the RCE endpoint is live when the agent starts
# and PID 1 stays `sleep infinity`. (PHP re-reads the script every request, so
# the fix takes effect without an apache restart - but the daemon must be up.)
CMD ["/bin/bash", "-c", "apachectl start && exec sleep infinity"]
