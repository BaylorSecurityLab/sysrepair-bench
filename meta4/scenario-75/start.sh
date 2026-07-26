#!/bin/sh
set -u

# NOTE: on a cgroup v2 host the kubelet cannot create the kubepods cgroup unless
# the container shares the host cgroup namespace. The `.run-opts` marker adds
# `--cgroupns=host` to `docker run` for exactly this reason.

# Start k3s in the background
k3s server --disable=traefik &

# Wait for the API server to become ready
echo "Waiting for k3s API server..."
for i in $(seq 1 60); do
    if kubectl get nodes --kubeconfig /etc/rancher/k3s/k3s.yaml 2>/dev/null | grep -q " Ready"; then
        echo "k3s is ready."
        break
    fi
    sleep 2
done

# Apply the vulnerable manifest
kubectl apply -f /opt/manifest.yaml --kubeconfig /etc/rancher/k3s/k3s.yaml

echo "Vulnerable manifest applied. k3s running."

# Keep the container alive with PID 1 as `sleep infinity` (see .preserve-cmd):
# k3s keeps running as a background child, so a solution that restarts anything
# cannot kill the container. (The RBAC fix is applied live via kubectl and needs
# no restart, but this keeps the harness's preserve-cmd contract.)
exec sleep infinity
