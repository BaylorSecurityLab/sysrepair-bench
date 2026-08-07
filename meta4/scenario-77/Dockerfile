FROM --platform=linux/amd64 rancher/k3s:v1.27.1-k3s1

# K8s Config Hardening misconfiguration: pods deployed without CPU/memory
# resource limits allow unbounded resource consumption, enabling noisy-neighbour
# denial-of-service against co-located workloads.

COPY start.sh /opt/start.sh
COPY manifest.yaml /opt/manifest.yaml
# rancher/k3s ships NO /etc/passwd, so `docker exec -u root` fails with
# "unable to find user root: no matching entries in passwd file".
# inspect's sandbox-tool injection execs as root, so every k3s scenario
# errored out unscored in a real eval while the gate runner passed them --
# it does not exec as a named user. Found only by running the harness.
RUN echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd \
 && echo 'root:x:0:' > /etc/group \
 && chmod +x /opt/start.sh

EXPOSE 6443

ENTRYPOINT []
CMD ["/opt/start.sh"]
