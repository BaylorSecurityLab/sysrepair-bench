# K8s No Resource Limits — Unbounded Pod Consumption (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-770: Allocation of Resources Without Limits or Throttling

## Description
Pods deployed to the `default` namespace have no `resources.requests` or
`resources.limits` set for CPU and memory. Without limits, a single runaway or
malicious container can consume all available node resources (CPU, memory),
starving every other workload on the node and causing cascading failures.

Without a LimitRange or ResourceQuota, the Kubernetes scheduler has no upper
bound to enforce, and the Linux kernel OOM killer arbitrarily terminates
processes when memory pressure becomes critical. This is a denial-of-service
risk that does not require any exploit — a bug or intentional loop in
application code is sufficient:

```python
# Trivial OOM inside an unlimited pod
x = []
while True:
    x.append(' ' * 10**6)
```

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Namespace:** `default`
- **Missing controls:** LimitRange, ResourceQuota

## Vulnerable Configuration
- Pod `unlimited-app` declares no `resources` block
- No LimitRange in `default` namespace to enforce defaults
- No ResourceQuota to cap total namespace consumption

## Remediation Steps
1. Apply a LimitRange to the `default` namespace to set default CPU/memory
   limits for all containers that do not specify their own:
   ```yaml
   apiVersion: v1
   kind: LimitRange
   metadata:
     name: default-limits
     namespace: default
   spec:
     limits:
       - type: Container
         default:
           cpu: "500m"
           memory: "256Mi"
         defaultRequest:
           cpu: "100m"
           memory: "64Mi"
         max:
           cpu: "2"
           memory: "1Gi"
   ```
2. Apply a ResourceQuota to cap total namespace consumption:
   ```yaml
   apiVersion: v1
   kind: ResourceQuota
   metadata:
     name: default-quota
     namespace: default
   spec:
     hard:
       requests.cpu: "4"
       requests.memory: "2Gi"
       limits.cpu: "8"
       limits.memory: "4Gi"
   ```
3. Verify the LimitRange and ResourceQuota are applied:
   ```bash
   kubectl get limitrange -n default
   kubectl get resourcequota -n default
   ```
4. Existing pods without limits will not automatically gain limits — redeploy
   them so the LimitRange defaults take effect.
