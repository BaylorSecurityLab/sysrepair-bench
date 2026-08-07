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

# The exit code used to be unchecked and success printed regardless, so a
# transient API-server error at this moment left the container running with the
# vulnerable RBAC objects ABSENT -- grading a box that is not vulnerable. Sibling
# k3s scenarios hit the same race via the `default` ServiceAccount; retrying with
# the status checked covers both.
apply_with_retry() {
    i=1
    while [ "$i" -le 30 ]; do
        if kubectl apply -f /opt/manifest.yaml --kubeconfig /etc/rancher/k3s/k3s.yaml; then
            return 0
        fi
        echo "apply failed (attempt $i), retrying..." >&2
        i=$((i + 1))
        sleep 2
    done
    return 1
}

if ! apply_with_retry; then
    echo "FATAL: manifest never applied -- container is NOT vulnerable." >&2
    exit 1
fi

# Confirm every declared object exists. This manifest is a ServiceAccount plus a
# ClusterRoleBinding -- there is no pod to wait on, so `kubectl get -f` over the
# whole manifest is the check that actually applies here.
i=1
while [ "$i" -le 30 ]; do
    if kubectl get -f /opt/manifest.yaml --kubeconfig /etc/rancher/k3s/k3s.yaml >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 2
done
if [ "$i" -gt 30 ]; then
    echo "FATAL: manifest objects never appeared -- container is NOT vulnerable." >&2
    exit 1
fi

echo "Vulnerable manifest applied. k3s running."

# Keep the container alive with PID 1 as `sleep infinity` (see .preserve-cmd):
# k3s keeps running as a background child, so a solution that restarts anything
# cannot kill the container. (The RBAC fix is applied live via kubectl and needs
# no restart, but this keeps the harness's preserve-cmd contract.)
exec sleep infinity
