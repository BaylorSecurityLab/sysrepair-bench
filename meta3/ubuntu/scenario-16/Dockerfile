FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g; s|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    apt-get update && apt-get clean

# Install MySQL 5.5 and supporting tools
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        mysql-server-5.5 \
        mysql-client-5.5 \
        tcpd \
        iproute \
        net-tools \
    && apt-get clean

# Seed vulnerable configuration: bind MySQL to 0.0.0.0 (all interfaces)
RUN sed -i 's/^bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/my.cnf && \
    grep -q 'bind-address' /etc/mysql/my.cnf || \
    sed -i '/^\[mysqld\]/a bind-address = 0.0.0.0' /etc/mysql/my.cnf

# Ensure skip-networking is off (we want it reachable -- that is the vuln state)
RUN sed -i '/^skip-networking/d' /etc/mysql/my.cnf

# Create a trusted application user for regression testing
RUN service mysql start && \
    mysql -u root -e "CREATE USER IF NOT EXISTS 'trusted_user'@'localhost' IDENTIFIED BY 'TrustedP@ss1';" && \
    mysql -u root -e "GRANT SELECT ON *.* TO 'trusted_user'@'localhost';" && \
    mysql -u root -e "FLUSH PRIVILEGES;" && \
    service mysql stop

# Seed /etc/hosts.allow and /etc/hosts.deny with open (vulnerable) defaults
RUN echo '# No restrictions -- vulnerable default' > /etc/hosts.allow && \
    echo '# No blanket deny -- vulnerable default' > /etc/hosts.deny

COPY scenario-16/verify.sh /verify.sh
RUN chmod +x /verify.sh

EXPOSE 3306

CMD ["bash", "-c", "service mysql start && tail -f /var/log/mysql/error.log 2>/dev/null || sleep infinity"]
