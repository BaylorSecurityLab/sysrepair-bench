# Scenario 35: NFS Server Unnecessarily Exposed

## Vulnerability
The NFS (Network File System) server is installed and configured with insecure exports. The `/srv/nfs` directory is exported to all hosts (`*`) with `rw` (read-write) access and `no_root_squash`, which allows any remote root user to have full root privileges on the exported filesystem. This configuration allows:
- Any host on the network to mount and access the share.
- Remote root users to create SUID binaries, modify files, and escalate privileges.
- Data exfiltration and unauthorized modification.

## CWE Classification
- **CWE-284**: Improper Access Control
- NFS exports are configured without proper host restrictions or privilege squashing.

## Affected Components
- `/etc/exports` - NFS export configuration (wildcard with no_root_squash)
- `nfs-kernel-server` service - Running and enabled
- `/srv/nfs` - Exported directory with world access

## Expected Remediation
Option A (Remove NFS if not needed):
1. Stop and disable the NFS server service.
2. Remove or purge the `nfs-kernel-server` package.
3. Clean up `/etc/exports`.

Option B (Secure NFS if needed):
1. Restrict exports to specific IP addresses or subnets (not `*`).
2. Remove `no_root_squash` (use `root_squash` instead).
3. Use `ro` (read-only) where possible.
4. Add `secure` option to require privileged ports.
5. Consider adding Kerberos authentication.
6. Restart the NFS server to apply changes.

## References
- CIS Ubuntu Linux Benchmark - Section 2.2.7 (Ensure NFS is not enabled)
- NIST SP 800-123 (Guide to General Server Security)
- TAMU remove_nfs.sh
