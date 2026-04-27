FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN a2enmod cgi
RUN mkdir -p /usr/lib/cgi-bin && echo '#!/bin/bash\necho "Content-type: text/html"\necho ""\necho "CGI Test: $(date)"' > /usr/lib/cgi-bin/test.cgi && chmod 755 /usr/lib/cgi-bin/test.cgi
# Note: Debian 10 bash is patched, but the CGI setup mirrors the vulnerable config
EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
