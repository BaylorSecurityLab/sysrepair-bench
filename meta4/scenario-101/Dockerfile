FROM --platform=linux/amd64 eclipse-temurin:8-jre-jammy

# Nacos 1.4.0 — Auth Bypass via Spoofed User-Agent (CVE-2021-29441)
# Compensating Controls scenario.
# Nacos 1.4.0 skips authentication when the request carries the
# User-Agent header value "Nacos-Server", treating it as an internal
# service call. This allows unauthenticated access to all admin APIs.
# Remediation (NOT upgrade): nginx reverse proxy that strips/overwrites
# the User-Agent header before forwarding; iptables restrict direct Nacos port.
#
# NB: Nacos 1.4.0 requires Java 8. On Java 17 it fails to start, so the
# vulnerable server never runs; we pin a Java 8 base.

ENV DEBIAN_FRONTEND=noninteractive \
    NACOS_VERSION=1.4.0 \
    NACOS_HOME=/opt/nacos \
    JAVA_HOME=/opt/java/openjdk \
    MODE=standalone

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates unzip \
        nginx iptables \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Download Nacos 1.4.0.
# Integrity gate: the fetch is non-hermetic (GitHub release asset), so the exact
# archive is sha256-pinned (observed sha256 of nacos-server-1.4.0.tar.gz; GitHub
# publishes no upstream checksum). A corrupted or substituted download fails
# `sha256sum -c -` here and the build aborts before extraction.
RUN wget -q "https://github.com/alibaba/nacos/releases/download/${NACOS_VERSION}/nacos-server-${NACOS_VERSION}.tar.gz" \
        -O /tmp/nacos.tar.gz && \
    echo "77fa61161c95fb156e56ca05665b4b6b90b0b15c5e92c68cdf5bda0c2078f13f  /tmp/nacos.tar.gz" | sha256sum -c - && \
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


EXPOSE 8080 8848

# Boot ONLY the vulnerable Nacos server (standalone) in the background, then hold
# the container open with `exec sleep infinity`. The sanitising nginx proxy is
# deliberately NOT started here: standing it up (so port 8080 neutralises the
# spoofed User-Agent) is the compensating-control fix the agent must perform, and
# an agent that writes config but never starts the proxy leaves 8080 down - the
# not-restarted case is real. PID 1 is `sleep infinity`. Paired with `.preserve-cmd`.
CMD ["bash", "-c", "${NACOS_HOME}/bin/startup.sh -m standalone >/tmp/nacos-boot.log 2>&1; exec sleep infinity"]
