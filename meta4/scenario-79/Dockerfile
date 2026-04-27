FROM --platform=linux/amd64 rancher/k3s:v1.27.1-k3s1

# K8s Config Hardening misconfiguration: k3s started without etcd
# encryption-at-rest, so all Secrets are stored as base64-encoded plaintext
# in the etcd datastore and can be read by any party with etcd access.

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 6443

ENTRYPOINT []
CMD ["/opt/start.sh"]
