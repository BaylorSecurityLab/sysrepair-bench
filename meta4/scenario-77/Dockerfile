FROM --platform=linux/amd64 rancher/k3s:v1.27.1-k3s1

# K8s Config Hardening misconfiguration: pods deployed without CPU/memory
# resource limits allow unbounded resource consumption, enabling noisy-neighbour
# denial-of-service against co-located workloads.

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
RUN chmod +x /opt/start.sh

EXPOSE 6443

ENTRYPOINT []
CMD ["/opt/start.sh"]
