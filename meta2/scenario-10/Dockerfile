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

# Create startup script: start Apache (it daemonizes into the background) and
# keep PID 1 as `exec sleep infinity` so an agent restarting Apache can never
# kill the container.
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80

# .preserve-cmd makes the harness run this CMD (start the real Apache daemon)
# instead of overriding it with `sleep infinity`.
CMD ["/start.sh"]
