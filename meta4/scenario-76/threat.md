# K8s No NetworkPolicy — Flat Networking (misconfig)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Kubernetes does not enforce any pod-to-pod traffic restrictions unless
NetworkPolicy objects are explicitly applied. Without a default-deny
NetworkPolicy in the `secure-middleware` namespace, any pod anywhere in the
cluster — including potentially compromised workloads in other namespaces —
can send traffic directly to pods in `secure-middleware` on any port.

This violates the principle of least privilege at the network layer: a
compromised frontend pod in the `default` namespace can freely probe and
attack backend services in `secure-middleware` as if they were on the same
flat network.

```bash
# From any pod in the cluster:
wget -qO- http://<secure-middleware-pod-ip>:<port>
# succeeds with no NetworkPolicy present
```

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Namespace:** `secure-middleware`
- **Missing control:** Default-deny ingress NetworkPolicy

## Vulnerable Configuration
- Namespace `secure-middleware` has no NetworkPolicy objects
- Default Kubernetes behavior: all ingress and egress is permitted
- Any pod in any namespace can reach any pod in `secure-middleware`

## Remediation Steps
1. Apply a default-deny ingress NetworkPolicy to the `secure-middleware`
   namespace to block all inbound traffic unless explicitly allowed:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny-ingress
     namespace: secure-middleware
   spec:
     podSelector: {}
     policyTypes:
       - Ingress
   ```
2. Add explicit allow rules only for traffic that is required:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: allow-from-frontend
     namespace: secure-middleware
   spec:
     podSelector:
       matchLabels:
         app: middleware
     policyTypes:
       - Ingress
     ingress:
       - from:
           - namespaceSelector:
               matchLabels:
                 kubernetes.io/metadata.name: frontend
   ```
3. Verify the NetworkPolicy is applied:
   ```bash
   kubectl get networkpolicy -n secure-middleware
   ```
4. Consider also applying a default-deny egress policy to prevent data
   exfiltration from compromised pods.
