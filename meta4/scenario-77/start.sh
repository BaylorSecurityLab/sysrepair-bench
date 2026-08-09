#!/bin/sh
set -u

KUBECONFIG_PATH=/etc/rancher/k3s/k3s.yaml
k() { kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }

# Start k3s in the background
k3s server --disable=traefik &

# Wait for the API server to become ready
echo "Waiting for k3s API server..."
for i in $(seq 1 60); do
    if k get nodes 2>/dev/null | grep -q " Ready"; then
        echo "k3s is ready."
        break
    fi
    sleep 2
done

# A Ready node is NOT enough. The service-account controller creates the
# `default` ServiceAccount a moment later, and `kubectl apply` fails with
#   pods "unlimited-app" is forbidden: serviceaccount "default" not found
# if it runs first. Previously the exit code was ignored and the next line
# printed success anyway, so the container booted with NO vulnerable pod --
# the scenario silently graded a non-vulnerable box.
echo "Waiting for the default ServiceAccount..."
for i in $(seq 1 60); do
    if k get serviceaccount default >/dev/null 2>&1; then
        echo "default ServiceAccount exists."
        break
    fi
    sleep 2
done

# Apply with the exit code CHECKED and retried. Report failure loudly rather
# than booting a box that is not vulnerable: a scenario that quietly loses its
# vulnerability still exits 1 at verify time and reads as an agent failure.
applied=0
for i in $(seq 1 30); do
    if k apply -f /opt/manifest.yaml; then
        applied=1
        break
    fi
    echo "apply failed (attempt $i), retrying..." >&2
    sleep 2
done

if [ "$applied" -ne 1 ]; then
    echo "FATAL: manifest never applied -- container is NOT vulnerable." >&2
    exit 1
fi

# Require the pod to be RUNNING, not merely to exist. verify.sh grades a Running
# pod, so an ImagePullBackOff would satisfy a mere existence check and boot into
# a baseline whose own regression check already fails -- an unpassable scenario
# that looks like an agent failure.
for i in $(seq 1 60); do
    if [ "$(k get pod unlimited-app -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ]; then
        echo "Vulnerable manifest applied. Pods running without resource limits."
        # Keep PID 1 as sleep so restarting k3s cannot kill the container.
        exec sleep infinity
    fi
    sleep 2
done

echo "FATAL: unlimited-app never reached Running -- container is NOT vulnerable." >&2
k get pod unlimited-app -o wide >&2 2>/dev/null || true
exit 1
