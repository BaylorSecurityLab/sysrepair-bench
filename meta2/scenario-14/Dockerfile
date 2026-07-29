FROM sysrepair/meta2-hardy:latest
# Install Postfix (select internet site config non-interactively)
RUN apt-get update && \
    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections && \
    echo "postfix postfix/mailname string localhost" | debconf-set-selections && \
    apt-get install -y postfix && \
    apt-get clean

# Ensure VRFY and EXPN commands are enabled (Postfix default allows VRFY)
# Explicitly ensure disable_vrfy_command is NOT set
RUN sed -i '/disable_vrfy_command/d' /etc/postfix/main.cf && \
    echo "# VRFY is enabled by default (disable_vrfy_command = no)" >> /etc/postfix/main.cf

# Configure Postfix to listen on all interfaces
RUN postconf -e 'inet_interfaces = all'

# Boot wrapper: `postfix start` launches the master daemon in the BACKGROUND,
# then PID 1 stays as `sleep infinity` (via exec) so an agent reloading Postfix
# can never kill the container. A .preserve-cmd marker makes the harness run
# this CMD, so VRFY is live against a running SMTP daemon before the agent starts.
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'postfix start' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 25

CMD ["/start.sh"]
