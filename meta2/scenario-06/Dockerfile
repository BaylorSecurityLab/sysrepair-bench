FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install MySQL server non-interactively with empty root password
RUN apt-get update && \
    echo "mysql-server mysql-server/root_password password " | debconf-set-selections && \
    echo "mysql-server mysql-server/root_password_again password " | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server mysql-client && \
    apt-get clean

# Configure MySQL to listen on all interfaces (the vulnerability)
RUN sed -i 's/^bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/my.cnf

# Initialize MySQL data directory if needed
RUN mkdir -p /var/run/mysqld && \
    chown mysql:mysql /var/run/mysqld

# Expose MySQL port
EXPOSE 3306

# Start MySQL in foreground
CMD ["mysqld_safe"]
