FROM ubuntu:25.10
# Scenario 38: Compiler tools (gcc/make) on production
# CWE-1104: Use of Unmaintained Third Party Components
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    gcc g++ make build-essential cmake autoconf automake \
    nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set up a simple web server (the "production" service)
RUN echo '<html><body><h1>Production Server</h1></body></html>' > /var/www/html/index.html

# Create a user
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd


EXPOSE 80
# Boot the production service, then hold the container open with `sleep
# infinity` (paired with the `.preserve-cmd` marker). `-g 'daemon off;'` is
# dropped so nginx daemonises and control reaches the `exec`, which keeps PID 1
# stable: an agent restarting nginx cannot kill the container, and the web
# server is genuinely LIVE while the toolchain purge happens - so a purge that
# rips out the C runtime and bricks nginx is caught for real.
CMD ["/bin/bash", "-c", "nginx && exec sleep infinity"]
