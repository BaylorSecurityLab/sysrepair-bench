FROM --platform=linux/amd64 debian:bookworm-slim

# Metabase 0.46.6 — Pre-auth RCE via H2 JDBC Injection (CVE-2023-38646)
# Compensating Controls scenario.
# The /api/setup/validate endpoint processes a JDBC connection string
# (including driver class and URL) without authentication. When the H2
# database type is selected, an attacker can inject a malicious H2 URL
# with INIT= directives to execute arbitrary OS commands → pre-auth RCE.
# Remediation (NOT upgrade): nginx reverse proxy blocking /api/setup/validate;
# switch MB_DB_TYPE to postgres (removes H2 JDBC path).

ENV DEBIAN_FRONTEND=noninteractive \
    METABASE_VERSION=v0.46.6 \
    MB_DB_TYPE=postgres \
    MB_DB_DBNAME=metabase \
    MB_DB_PORT=5432 \
    MB_DB_USER=metabase \
    MB_DB_PASS=metabase \
    MB_DB_HOST=localhost

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates \
        openjdk-11-jre-headless \
        nginx \
        netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

# Download Metabase 0.46.6 JAR
RUN wget -q "https://downloads.metabase.com/${METABASE_VERSION}/metabase.jar" \
        -O /opt/metabase.jar

# nginx reverse proxy: block /api/setup/validate endpoint
RUN cat > /etc/nginx/sites-available/metabase <<'EOF'
server {
    listen 3000;

    # Block the vulnerable pre-auth RCE endpoint
    location = /api/setup/validate {
        return 403 "Forbidden: endpoint disabled by security policy.\n";
    }

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300;
    }
}
EOF
RUN ln -sf /etc/nginx/sites-available/metabase \
        /etc/nginx/sites-enabled/metabase && \
    rm -f /etc/nginx/sites-enabled/default

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 3000

CMD ["bash", "-c", \
    "nginx & \
     java -jar /opt/metabase.jar & \
     sleep infinity"]
