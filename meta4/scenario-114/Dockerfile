FROM --platform=linux/amd64 debian:bookworm-slim

# Simulated Cacti command injection via remote_agent.php (CVE-2022-46169).
# CWE-78 / CVSS 9.8. Unauthenticated command injection.
# Vulnerable state: Apache+PHP serving remote_agent.php with no access controls.
# Remediation (compensating control): nginx proxy denying remote_agent.php
# from non-localhost. NOT an upgrade.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apache2 \
        php \
        libapache2-mod-php \
        curl \
        iproute2 \
        iptables \
        nginx \
        && \
    rm -rf /var/lib/apt/lists/*

# Simulate Cacti login page
RUN cat > /var/www/html/index.php << 'EOF'
<?php
header('Content-Type: text/html');
?>
<html>
<head><title>Cacti - Login</title></head>
<body>
<h1>Cacti - Network Monitoring</h1>
<form method="post" action="index.php">
  <label>Username: <input type="text" name="login_username"></label><br>
  <label>Password: <input type="password" name="login_password"></label><br>
  <input type="submit" value="Login">
</form>
<p>Version: 1.2.22 (simulated)</p>
</body>
</html>
EOF

# Simulate vulnerable remote_agent.php
RUN cat > /var/www/html/remote_agent.php << 'EOF'
<?php
// Simulated CVE-2022-46169 vulnerable endpoint.
// In real Cacti, the $local_data_id parameter is passed to poller.php
// without sanitisation, allowing OS command injection.
$action = isset($_GET['action']) ? $_GET['action'] : 'polldata';
$host_id = isset($_GET['host_id']) ? $_GET['host_id'] : '1';
// Simulate command injection
$output = shell_exec("echo polled_host_id=" . escapeshellarg($host_id));
header('Content-Type: text/plain');
echo "REMOTE_AGENT_RESPONSE\n";
echo "action=$action\n";
echo $output;
EOF

# Enable Apache mod_php and configure
RUN a2enmod php8.2 || a2enmod php || true
RUN echo "Listen 8080" > /etc/apache2/ports.conf && \
    sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' \
        /etc/apache2/sites-available/000-default.conf

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80 8080

CMD ["/opt/start.sh"]
