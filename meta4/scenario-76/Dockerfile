FROM --platform=linux/amd64 rancher/k3s:v1.27.1-k3s1

# K8s Network Security misconfiguration: flat networking with no NetworkPolicy
# allows any pod to reach any other pod across all namespaces without restriction.

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
RUN chmod +x /opt/start.sh

EXPOSE 6443

ENTRYPOINT []
CMD ["/opt/start.sh"]
