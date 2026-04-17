FROM sysrepair/meta2-hardy:latest
# Install Apache 2.2
RUN apt-get update && \
    apt-get install -y apache2 && \
    apt-get clean

# Ensure TraceEnable is On (Apache 2.2 default)
# Explicitly set it in config to make the vulnerability clear
RUN echo "TraceEnable On" >> /etc/apache2/apache2.conf

# Create a basic index page
RUN echo '<html><body><h1>Welcome to the server</h1></body></html>' > /var/www/index.html

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
