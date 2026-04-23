FROM --platform=linux/amd64 rancher/k3s:v1.27.1-k3s1

# K8s RBAC misconfiguration: ServiceAccount 'superadmin' in the default
# namespace is bound to the built-in cluster-admin ClusterRole, granting
# unrestricted access to every resource across the entire cluster.

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/start.sh /opt/verify.sh

EXPOSE 6443

ENTRYPOINT []
CMD ["/opt/start.sh"]
