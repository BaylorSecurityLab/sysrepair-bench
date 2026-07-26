FROM --platform=linux/amd64 registry:2

# Docker Registry 2 — No Authentication (misconfig)
# The registry is started without any authentication backend configured.
# Anyone with network access can list, pull, and push images without credentials.
#
# Vulnerable: REGISTRY_AUTH is not set, so the registry accepts all requests.
# Remediation: Set REGISTRY_AUTH=htpasswd and configure htpasswd credentials.
#
# Example remediation environment variables:
#   REGISTRY_AUTH=htpasswd
#   REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm
#   REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd

RUN apk add --no-cache curl apache2-utils bash

# Create htpasswd file for remediation use (admin:password)
RUN mkdir -p /auth && \
    htpasswd -Bbn admin password > /auth/htpasswd


EXPOSE 5000

# Boot wrapper (see .preserve-cmd): start the registry with NO auth in the
# BACKGROUND then exec `sleep infinity`, so PID 1 is the wrapper. This keeps the
# unauthenticated registry live when the agent starts and lets a solution
# restart the registry (with auth) without killing the container.
ENTRYPOINT []
CMD ["/bin/bash", "-c", "registry serve /etc/docker/registry/config.yml & exec sleep infinity"]
