FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 rsyslog && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN touch /var/log/auth.log && chmod 666 /var/log/auth.log
RUN mkdir -p /var/log/apache2 && touch /var/log/apache2/access.log && chmod 666 /var/log/apache2/access.log
EXPOSE 80
# Boot wrapper: start rsyslog + apache in the background, then exec sleep as PID 1
# (see .preserve-cmd).
CMD ["/bin/bash", "-c", "rsyslogd; apachectl start; exec sleep infinity"]
