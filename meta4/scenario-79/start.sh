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

# Create a test secret that will be stored as plaintext base64 in etcd
kubectl create secret generic test-secret \
    --from-literal=password=s3cr3t-value \
    --kubeconfig /etc/rancher/k3s/k3s.yaml \
    2>/dev/null || true

echo "Test secret created. k3s running without etcd encryption."
wait
