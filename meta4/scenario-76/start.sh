#!/bin/sh
set -u

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

# A Ready node is NOT enough. This manifest creates a namespace AND a pod in it,
# and the service-account controller needs a moment to create that namespace's
# `default` ServiceAccount. Applying too early fails with
#   pods "middleware-app" is forbidden: serviceaccount "default" not found
# The exit code used to be unchecked and the next line printed success anyway,
# so the container booted with NO pod -- the scenario graded a box that was not
# vulnerable at all.
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

# Confirm every object the manifest declares actually exists. `apply` can report
# success against a stale cache, and the point of the scenario is that the
# objects are really there. `kubectl get -f` checks the whole manifest, so this
# stays correct if the manifest gains objects later.
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

echo "Vulnerable manifest applied. k3s running with flat networking."

# Keep PID 1 as sleep so an agent that restarts k3s cannot kill the container.
# k3s keeps running as a background child; a fix must RESTART it, not merely
# start it if absent.
exec sleep infinity
