FROM --platform=linux/amd64 rancher/k3s:v1.27.1-k3s1

# k3s insecure kubelet — read-only port and anonymous auth (misconfig).
# The kubelet read-only port (10255) is enabled, exposing pod metadata
# without authentication. Anonymous auth on the kubelet API (10250)
# is also enabled.

ENV K3S_KUBECONFIG_MODE="644"

# rancher/k3s ships NO /etc/passwd, so `docker exec -u root` fails with
# "unable to find user root: no matching entries in passwd file". inspect's
# sandbox-tool injection execs as root, so this scenario errored out UNSCORED
# for every model while the gate runner passed it (the gate does not exec as a
# named user). The five sibling k3s scenarios already carry this fix; this one
# was missed.
RUN echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd \
 && echo 'root:x:0:' > /etc/group

# Boot wrapper (NOT a bare foreground CMD): it starts k3s with the vulnerable
# kubelet args in the BACKGROUND and then `exec sleep infinity`, so PID 1 stays
# `sleep infinity`. That makes the "fixed the args but forgot to restart" case
# detectable and means an agent restarting k3s cannot kill the container.
#
# It also performs the cgroup-v2 leaf-nesting shuffle (move all procs to a
# child cgroup and delegate the controllers to subtree_control). Without this,
# k3s' kubelet dies at boot on a cgroup-v2 host with
# "cannot enter cgroupv2 kubepods with domain controllers -- invalid state"
# and the container exits (the scenario would ship not-vulnerable).
RUN cat > /boot.sh <<'BASH'
#!/bin/sh
# --- cgroup v2 leaf nesting so the kubelet can create /sys/fs/cgroup/kubepods
if [ -f /sys/fs/cgroup/cgroup.controllers ] && [ -w /sys/fs/cgroup/cgroup.subtree_control ]; then
    mkdir -p /sys/fs/cgroup/init 2>/dev/null || true
    for p in $(cat /sys/fs/cgroup/cgroup.procs 2>/dev/null); do
        echo "$p" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
    done
    sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
fi

# --- start k3s with the INSECURE kubelet args (the seeded misconfiguration).
# Run it inside a subshell that immediately exits, so k3s is reparented to PID 1
# (tini, from --init) which REAPS it. k3s has no --fork/daemonize option, so if
# it stayed a child of `sleep infinity` (a non-reaping process) it would become
# a permanent zombie on kill and keep port 6443 pinned — breaking any restart.
( k3s server \
    --kubelet-arg=read-only-port=10255 \
    --kubelet-arg=anonymous-auth=true \
    --disable=traefik \
    --write-kubeconfig-mode=644 >/var/log/k3s.log 2>&1 & )

# --- best-effort readiness poll (never fails the container)
i=0
while [ "$i" -lt 60 ]; do
    if KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get nodes 2>/dev/null | grep -q ' Ready'; then
        break
    fi
    i=$((i+1)); sleep 2
done

exec sleep infinity
BASH
RUN chmod +x /boot.sh


EXPOSE 6443 10250 10255
ENTRYPOINT []
CMD ["/bin/sh","/boot.sh"]
