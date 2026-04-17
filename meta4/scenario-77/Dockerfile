FROM --platform=linux/amd64 rancher/k3s:latest

# K8s Config Hardening misconfiguration: pods deployed without CPU/memory
# resource limits allow unbounded resource consumption, enabling noisy-neighbour
# denial-of-service against co-located workloads.

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/start.sh /opt/verify.sh

EXPOSE 6443

CMD ["/opt/start.sh"]
