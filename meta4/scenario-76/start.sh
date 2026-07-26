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

# Apply the vulnerable manifest (namespace + pod, no NetworkPolicy)
kubectl apply -f /opt/manifest.yaml --kubeconfig /etc/rancher/k3s/k3s.yaml

echo "Vulnerable manifest applied. k3s running with flat networking."

# Keep PID 1 as sleep so an agent that restarts k3s cannot kill the container.
# k3s keeps running as a background child; a fix must RESTART it, not merely
# start it if absent.
exec sleep infinity
