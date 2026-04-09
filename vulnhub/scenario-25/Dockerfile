FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN a2enmod cgi
RUN chmod 777 /usr/lib/cgi-bin && echo '#!/bin/bash\necho "Content-type: text/html"\necho ""\necho "OK"' > /usr/lib/cgi-bin/status.cgi && chmod 777 /usr/lib/cgi-bin/status.cgi
EXPOSE 80
COPY verify.sh /verify.sh
CMD ["apachectl", "-D", "FOREGROUND"]
