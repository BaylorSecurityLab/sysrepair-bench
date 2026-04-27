FROM ubuntu:25.10
# Scenario 08: Apache TRACE method enabled
# CWE-693: Protection Mechanism Failure
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable TRACE method (vulnerable)
RUN echo 'TraceEnable On' >> /etc/apache2/conf-enabled/security.conf

# Create a test page
RUN echo '<html><body><h1>Test Page</h1></body></html>' > /var/www/html/index.html


EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
