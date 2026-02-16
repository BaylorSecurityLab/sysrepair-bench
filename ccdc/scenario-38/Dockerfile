FROM ubuntu:rolling
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

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
