FROM --platform=linux/amd64 debian:bookworm-slim

# Nacos 1.4.0 — Auth Bypass via Spoofed User-Agent (CVE-2021-29441)
# Compensating Controls scenario.
# Nacos 1.4.0 skips authentication when the request carries the
# User-Agent header value "Nacos-Server", treating it as an internal
# service call. This allows unauthenticated access to all admin APIs.
# Remediation (NOT upgrade): nginx reverse proxy that strips/overwrites
# the User-Agent header before forwarding; iptables restrict direct Nacos port.

ENV DEBIAN_FRONTEND=noninteractive \
    NACOS_VERSION=1.4.0 \
    NACOS_HOME=/opt/nacos

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates unzip \
        openjdk-17-jre-headless \
        nginx iptables \
        netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

# Download Nacos 1.4.0
RUN wget -q "https://github.com/alibaba/nacos/releases/download/${NACOS_VERSION}/nacos-server-${NACOS_VERSION}.tar.gz" \
        -O /tmp/nacos.tar.gz && \
    tar xzf /tmp/nacos.tar.gz -C /opt && \
    rm /tmp/nacos.tar.gz

# Standalone mode config
RUN sed -i 's|^#.*nacos.core.auth.enabled.*|nacos.core.auth.enabled=true|' \
        ${NACOS_HOME}/conf/application.properties 2>/dev/null || true && \
    echo "nacos.core.auth.enabled=true" >> ${NACOS_HOME}/conf/application.properties

# nginx reverse proxy config — strips User-Agent before forwarding
RUN cat > /etc/nginx/sites-available/nacos <<'EOF'
server {
    listen 8080;

    location / {
        # Overwrite any client-supplied User-Agent to prevent spoofing
        proxy_set_header User-Agent "nginx-proxy";
        proxy_pass http://127.0.0.1:8848;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF
RUN ln -sf /etc/nginx/sites-available/nacos /etc/nginx/sites-enabled/nacos && \
    rm -f /etc/nginx/sites-enabled/default

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 8080 8848

CMD ["bash", "-c", \
    "${NACOS_HOME}/bin/startup.sh -m standalone & \
     sleep 10 && nginx -g 'daemon off;' & \
     wait"]
