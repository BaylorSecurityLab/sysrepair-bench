#!/bin/sh
set -u

# Start k3s WITHOUT encryption-at-rest (vulnerable default)
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

# Create the test secret that will be stored as plaintext base64 in etcd.
#
# This used to end in `2>/dev/null || true`, which discarded the failure
# outright: if the API server was not accepting writes yet, the container booted
# with NO secret and still printed success -- and the secret IS the scenario's
# whole premise, so it graded a box with nothing to find.
#
# Success is judged by the secret EXISTING, not by create's exit code, because
# `create` legitimately fails with AlreadyExists on a re-run.
i=1
while [ "$i" -le 30 ]; do
    kubectl create secret generic test-secret \
        --from-literal=password=s3cr3t-value \
        --kubeconfig /etc/rancher/k3s/k3s.yaml >/dev/null 2>&1

    if kubectl get secret test-secret \
        --kubeconfig /etc/rancher/k3s/k3s.yaml >/dev/null 2>&1; then
        break
    fi
    echo "secret not present yet (attempt $i), retrying..." >&2
    i=$((i + 1))
    sleep 2
done

if [ "$i" -gt 30 ]; then
    echo "FATAL: test-secret was never created -- container is NOT vulnerable." >&2
    exit 1
fi

echo "Test secret created. k3s running without etcd encryption."

# Keep PID 1 as sleep so an agent that restarts k3s (required to enable
# encryption-at-rest) cannot kill the container.
exec sleep infinity
