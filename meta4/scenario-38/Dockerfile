FROM --platform=linux/amd64 rancher/k3s:v1.27.1-k3s1

# k3s insecure kubelet — read-only port and anonymous auth (misconfig).
# The kubelet read-only port (10255) is enabled, exposing pod metadata
# without authentication. Anonymous auth on the kubelet API (10250)
# is also enabled.

# Seed: start k3s with insecure kubelet arguments
ENV K3S_KUBECONFIG_MODE="644"

RUN cat > /start.sh <<'BASH'
#!/bin/sh
exec k3s server \
    --kubelet-arg=read-only-port=10255 \
    --kubelet-arg=anonymous-auth=true \
    --disable=traefik \
    --write-kubeconfig-mode=644
BASH
RUN chmod +x /start.sh

COPY verify.sh /verify.sh
RUN chmod +x /verify.sh

EXPOSE 6443 10250 10255
CMD ["/start.sh"]
