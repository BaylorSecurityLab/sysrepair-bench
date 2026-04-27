FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 rsyslog && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN touch /var/log/auth.log && chmod 666 /var/log/auth.log
RUN mkdir -p /var/log/apache2 && touch /var/log/apache2/access.log && chmod 666 /var/log/apache2/access.log
EXPOSE 80
CMD rsyslogd && apachectl -D FOREGROUND
