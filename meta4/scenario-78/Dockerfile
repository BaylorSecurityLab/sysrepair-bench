FROM --platform=linux/amd64 rancher/k3s:latest

# K8s Network Security misconfiguration: internal service exposed via NodePort
# (30000+) making it reachable from outside the cluster on all node IPs,
# rather than being restricted to ClusterIP (cluster-internal only).

RUN apk add --no-cache bash

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/start.sh /opt/verify.sh

EXPOSE 6443

CMD ["/opt/start.sh"]
