FROM sysrepair/meta2-hardy:latest
# Install Apache 2.2 with PHP5
RUN apt-get update && \
    apt-get install -y apache2 libapache2-mod-php5 php5 && \
    apt-get clean

# Create phpinfo.php in the web root
RUN echo '<?php phpinfo(); ?>' > /var/www/phpinfo.php

# Create a legitimate PHP page to verify PHP still works after remediation
RUN echo '<?php echo "PHP is working"; ?>' > /var/www/test.php

# Create a basic index page
RUN echo '<html><body><h1>Welcome to the server</h1></body></html>' > /var/www/index.html

# Boot wrapper: apache2ctl start daemonizes httpd into the BACKGROUND, then we
# keep PID 1 as `sleep infinity` (via exec) so an agent restarting Apache can
# never kill the container. A .preserve-cmd marker makes the harness run this
# CMD, so the exposed phpinfo.php is live before the agent starts.
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
