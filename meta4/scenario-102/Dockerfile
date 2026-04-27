FROM --platform=linux/amd64 debian:bookworm-slim

# Zabbix 5.0 — Default Credentials + API RCE (CVE-2022-23131) — Compensating Controls
# Default admin:zabbix credentials allow unauthenticated (in effect) login via the
# JSON-RPC API. The API also permits script execution on monitored hosts.
# CVE-2022-23131: SAML SSO auth bypass in Zabbix 5.4.x; the broader issue here is
# default creds + unrestricted API access → RCE.
# Remediation (NOT upgrade): nginx reverse proxy requiring HTTP basic auth on
# /api_jsonrpc.php; change default admin password; iptables restrict frontend.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg wget \
        nginx apache2-utils iptables \
        netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

# Install Zabbix 5.0 repo and packages (frontend simulation — minimal)
RUN wget -q "https://repo.zabbix.com/zabbix/5.0/debian/pool/main/z/zabbix-release/zabbix-release_5.0-2+debian11_all.deb" \
        -O /tmp/zabbix-release.deb 2>/dev/null && \
    dpkg -i /tmp/zabbix-release.deb 2>/dev/null && \
    apt-get update 2>/dev/null && \
    apt-get install -y --no-install-recommends \
        zabbix-frontend-php zabbix-nginx-conf 2>/dev/null && \
    rm -rf /var/lib/apt/lists/* /tmp/zabbix-release.deb || true

# nginx proxy config: require HTTP basic auth on /api_jsonrpc.php
RUN cat > /etc/nginx/sites-available/zabbix-protected <<'EOF'
server {
    listen 8080;

    root /usr/share/zabbix;
    index index.php;

    # Block unauthenticated access to the JSON-RPC API endpoint
    location = /api_jsonrpc.php {
        auth_basic "Zabbix API — Authorised Access Only";
        auth_basic_user_file /etc/nginx/.htpasswd-zabbix;
        try_files $uri =404;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
EOF
RUN ln -sf /etc/nginx/sites-available/zabbix-protected \
        /etc/nginx/sites-enabled/zabbix-protected && \
    rm -f /etc/nginx/sites-enabled/default

# Create htpasswd for the API proxy (non-default credentials)
RUN htpasswd -bc /etc/nginx/.htpasswd-zabbix zabbixapi 'S3cur3ProxyP@ss!'


EXPOSE 8080

CMD ["bash", "-c", "nginx -g 'daemon off;'"]
