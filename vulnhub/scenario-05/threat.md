# Samba Wide Links Symlink Traversal

## Severity
**High** (CVSS 7.5)

## CVE
CVE-2010-0926

## Description
Samba is configured with `wide links = yes` which allows symlink traversal outside
of shared directories. An authenticated user can create symbolic links within a share
that point to arbitrary locations on the filesystem, allowing them to read files
outside the shared directory including /etc/shadow and other sensitive files.

This is a direct reproduction from the Metasploitable 2 VulnHub VM.

## Affected Service
- **Service:** Samba (smbd)
- **Port:** 139/TCP, 445/TCP
- **Configuration:** /etc/samba/smb.conf

## Vulnerable Configuration
```
[global]
    wide links = yes
```

## Remediation Steps
1. Edit `/etc/samba/smb.conf` and set `wide links = no` in [global]
2. Restart Samba: `service smbd restart`
