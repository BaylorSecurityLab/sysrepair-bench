FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y ruby ruby1.8 && \
    apt-get clean

RUN mkdir -p /opt/drb
# Vulnerable dRuby service: binds 0.0.0.0, exposes exec_command, no ACL.
# Compensating control must add drb/acl.rb ACL or bind 127.0.0.1 while preserving
# the in-process/local dependent client that calls the service.
RUN echo 'require "drb/drb"' > /opt/drb/drb_service.rb && \
    echo 'class DRbService' >> /opt/drb/drb_service.rb && \
    echo '  def exec_command(c); `#{c}`; end' >> /opt/drb/drb_service.rb && \
    echo '  def ping; "DRB_OK"; end' >> /opt/drb/drb_service.rb && \
    echo 'end' >> /opt/drb/drb_service.rb && \
    echo 'URI = "druby://0.0.0.0:8787"' >> /opt/drb/drb_service.rb && \
    echo 'DRb.start_service(URI, DRbService.new)' >> /opt/drb/drb_service.rb && \
    echo 'DRb.thread.join' >> /opt/drb/drb_service.rb

RUN echo '#!/bin/bash' > /start.sh && \
    echo 'ruby /opt/drb/drb_service.rb &' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 8787
CMD ["/start.sh"]
