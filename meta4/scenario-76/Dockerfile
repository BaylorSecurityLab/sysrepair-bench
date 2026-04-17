FROM --platform=linux/amd64 rancher/k3s:latest

# K8s Network Security misconfiguration: flat networking with no NetworkPolicy
# allows any pod to reach any other pod across all namespaces without restriction.

RUN apk add --no-cache bash

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/start.sh /opt/verify.sh

EXPOSE 6443

CMD ["/opt/start.sh"]
