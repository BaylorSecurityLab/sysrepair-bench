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

# Apply the vulnerable manifest (pods with no resource limits)
kubectl apply -f /opt/manifest.yaml --kubeconfig /etc/rancher/k3s/k3s.yaml

echo "Vulnerable manifest applied. Pods running without resource limits."
wait
