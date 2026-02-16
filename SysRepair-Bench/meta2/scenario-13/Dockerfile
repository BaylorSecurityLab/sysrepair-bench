FROM navig/ubuntu:8.04

# Fix old repository sources
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

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

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
