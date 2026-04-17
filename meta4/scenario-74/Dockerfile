FROM --platform=linux/amd64 ubuntu:22.04

# Docker Image Secrets in ENV/Layers (misconfig)
# Secrets baked into ENV instructions are permanently stored in image metadata
# and every intermediate layer. They are trivially recoverable via:
#   docker inspect <container> | grep -A 50 '"Env"'
#   docker history --no-trunc <image>
#
# Remediation: Remove ENV secrets. Pass secrets at runtime via:
#   - 'docker run -e DB_PASSWORD=$(vault kv get ...)'
#   - Docker Secrets (Swarm) or Kubernetes Secrets mounted as files
#   - A mounted config file read by the application at startup

# Vulnerable: secrets baked into the image
ENV DB_PASSWORD=SuperSecret123
ENV API_KEY=sk-live-abc123

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps && \
    rm -rf /var/lib/apt/lists/*

# Application entry point reads config from /run/secrets/config if present,
# otherwise falls back to environment variables (the vulnerable path).
RUN mkdir -p /app
COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

# Simple application script that uses mounted config when available
RUN cat > /app/start.sh << 'APPEOF'
#!/bin/bash
# Read config from mounted file if available (secure path)
if [ -f /run/secrets/config ]; then
    source /run/secrets/config
    echo "Config loaded from /run/secrets/config"
else
    echo "WARNING: No mounted config — using environment (may expose secrets)"
fi
echo "Application started."
exec sleep infinity
APPEOF
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
