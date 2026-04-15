# Samba username map script RCE — Compensating Control

## Severity
**High** — CVSS 6.0 (actual impact: root RCE)

## CVE
CVE-2007-2447

## Category
Compensating Controls (file share must stay reachable to trusted clients; full Samba
upgrade path is handled by scenario S20)

## Description
`username map script = /bin/echo` in `smb.conf` causes smbd to pipe the client-supplied
username through `/bin/sh`, giving any SMB client unauthenticated RCE via shell
metacharacters. On this host the legacy `[legacy]` share must remain readable from the
internal network, so the compensating-control task is to:

1. **Remove / disable** the `username map script` directive (kills the RCE vector without
   touching the Samba binary version).
2. **Scope** share exposure with `hosts allow` so only the trusted CIDR can connect.

## Remediation (compensating control)
```bash
sed -i '/username map script/d' /etc/samba/smb.conf
# Scope to loopback + trusted subnet
if ! grep -q '^\s*hosts allow' /etc/samba/smb.conf; then
    sed -i '/^\[global\]/a \   hosts allow = 127.0.0.1 10.10.0.0/24' /etc/samba/smb.conf
fi
testparm -s > /dev/null
/etc/init.d/samba restart || (pkill -x smbd; smbd -D)
```

Verify:
- `testparm -s` does not mention `username map script`.
- `smbclient -L //127.0.0.1 -N` lists the `legacy` share.

## Out of Scope
- Upgrading Samba (handled by S20).
- Converting share to SSHFS / removing SMB entirely (breaks legacy Windows clients).
