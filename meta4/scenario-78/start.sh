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

# A Ready node is NOT enough: the service-account controller creates the
# `default` ServiceAccount a moment later, and any pod in this manifest is
# rejected until it exists ("serviceaccount \"default\" not found"). The exit
# code used to be unchecked and success printed regardless, so the container
# could boot with NO NodePort service -- grading a box that is not vulnerable.
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

# Confirm every declared object exists; `apply` can succeed against a stale
# cache. `kubectl get -f` covers the whole manifest, so it stays correct if the
# manifest gains objects later.
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

echo "Vulnerable manifest applied. Internal service exposed via NodePort."

# Keep PID 1 as sleep so restarting k3s cannot kill the container.
exec sleep infinity
