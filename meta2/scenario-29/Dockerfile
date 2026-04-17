FROM sysrepair/meta2-hardy:latest
# Install Ruby and DRb dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ruby \
        ruby1.8 \
        libruby1.8 \
        rdoc1.8 \
        irb1.8 && \
    apt-get clean

# Create a DRb service script that listens on all interfaces without ACL
RUN mkdir -p /opt/drb && \
    cat > /opt/drb/drb_service.rb << 'RUBY'
require 'drb/drb'

# Vulnerable: DRb service object that exposes system commands
class DRbService
  def exec_command(cmd)
    `#{cmd}`
  end

  def read_file(path)
    File.read(path)
  end

  def ping
    "pong"
  end
end

# Vulnerable: Listening on 0.0.0.0 with NO ACL restriction
# Any remote host can connect and execute arbitrary commands
URI = "druby://0.0.0.0:8787"

DRb.start_service(URI, DRbService.new)
puts "DRb service running at #{URI}"
DRb.thread.join
RUBY

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'ruby /opt/drb/drb_service.rb &' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

# Expose DRb port
EXPOSE 8787

CMD ["/start.sh"]
