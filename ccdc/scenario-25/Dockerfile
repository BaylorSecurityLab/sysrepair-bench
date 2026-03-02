FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    redis-server \
    redis-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Configure Redis insecurely: bind to all interfaces with no authentication
RUN sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf && \
    sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf

# Ensure no requirepass is set (remove any existing requirepass line)
RUN sed -i '/^requirepass/d' /etc/redis/redis.conf

# Create entrypoint script to start Redis
RUN printf '#!/bin/bash\nredis-server /etc/redis/redis.conf --daemonize yes\nsleep infinity\n' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["/entrypoint.sh"]
