# K8s RBAC cluster-admin ServiceAccount (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-269: Improper Privilege Management

## Description
The ServiceAccount `superadmin` in the `default` namespace is bound directly
to the built-in `cluster-admin` ClusterRole via a ClusterRoleBinding. This
grants the service account — and any workload that mounts it — unrestricted
read, write, and delete access to every resource across every namespace in the
cluster, including Secrets, ConfigMaps, Pods, Nodes, and custom resources.

An attacker who can schedule a pod (or exec into an existing one) using this
service account can:

```bash
kubectl auth can-i '*' '*' --as=system:serviceaccount:default:superadmin
# → yes
```

This is equivalent to running as cluster root and bypasses all namespace-level
access boundaries.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Resource:** ClusterRoleBinding `superadmin-cluster-admin`
- **Vulnerable principal:** `system:serviceaccount:default:superadmin`

## Vulnerable Configuration
- ServiceAccount `superadmin` exists in namespace `default`
- ClusterRoleBinding binds it to `cluster-admin` (built-in super-admin role)
- No least-privilege scoping — any namespace, any resource, any verb

## Remediation Steps
1. Delete the over-privileged ClusterRoleBinding:
   ```bash
   kubectl delete clusterrolebinding superadmin-cluster-admin
   ```
2. Create a scoped Role that grants only the required permissions within a
   specific namespace:
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: superadmin-scoped
     namespace: default
   rules:
     - apiGroups: [""]
       resources: ["pods"]
       verbs: ["get", "list", "watch"]
   ```
3. Bind the ServiceAccount to the scoped Role with a RoleBinding (not a
   ClusterRoleBinding):
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: RoleBinding
   metadata:
     name: superadmin-scoped-binding
     namespace: default
   subjects:
     - kind: ServiceAccount
       name: superadmin
       namespace: default
   roleRef:
     kind: Role
     name: superadmin-scoped
     apiGroup: rbac.authorization.k8s.io
   ```
4. Verify the privilege is removed:
   ```bash
   kubectl auth can-i list secrets \
     --as=system:serviceaccount:default:superadmin
   # Expected: no
   ```
