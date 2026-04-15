# Samba USN-7826-2 -- WINS Hook RCE / streams_xattr Infoleak

## Severity
**Critical** (CVSS 9.8)

## CVE
- CVE-2025-10230 -- WINS hook script execution (RCE via crafted NetBIOS name registration)
- CVE-2025-9640 -- streams_xattr extended-attribute infoleak (arbitrary file read via VFS)

## Description

**CVE-2025-10230 (WINS hook RCE):**
Samba's WINS server can be configured to call an external `wins hook` script when
NetBIOS name registrations or releases occur. In the affected versions, a crafted
NetBIOS name containing shell metacharacters is passed to the hook script without
sanitization. An unauthenticated attacker on the network can send a specially
formed name registration packet to the WINS port (UDP 137) and cause Samba to
execute arbitrary shell commands as the user running `nmbd` (typically root).

**CVE-2025-9640 (streams_xattr infoleak):**
The `vfs_streams_xattr` VFS module, when loaded, exposes extended attribute streams
as alternate data streams. A logic flaw allows a client with read access to any
share to request the `::$DATA` alternate stream of a file outside the share's
chroot-equivalent path, leaking the content of arbitrary files accessible to the
Samba process (e.g., `/etc/shadow`, private keys).

Both CVEs are addressed in the Samba packages distributed via Ubuntu Security
Notice USN-7826-2.

## Affected Service
- **Service:** Samba (smbd / nmbd)
- **Port:** 445/TCP (SMB), 137/UDP (WINS/NetBIOS)
- **Package:** samba (Ubuntu 14.04: 2:4.1.6+dfsg-1ubuntu2 and earlier)

## Vulnerable Configuration
```
[global]
    wins support = yes
    wins hook = /usr/local/bin/wins-notify.sh   # if present
    vfs objects = streams_xattr                  # if present on any share
```
The container ships with the vulnerable package version. `wins support` and
`streams_xattr` are not explicitly enabled in the seed config, but the binaries
contain the unpatched code paths.

## Remediation Steps
1. Update the Samba package to the USN-7826-2 patched version. Since Ubuntu 14.04
   is EOL, fetch the patched build from the Ubuntu ESM archive or install a
   manually backported package:
   ```
   apt-get update
   apt-get install --only-upgrade samba samba-common samba-common-bin
   ```
   If ESM is unavailable, compile Samba 4.19.x from source with the upstream patches:
   ```
   # Download Samba 4.19.x source and apply CVE-2025-10230 / CVE-2025-9640 patches
   # then: ./configure && make && make install
   ```
2. As an immediate mitigation while patching, add to `/etc/samba/smb.conf`:
   ```
   [global]
       wins support = no
       wins hook =
   ```
   And remove `streams_xattr` from any `vfs objects` lines.
3. Reload Samba:
   ```
   /etc/init.d/samba reload
   ```
4. Verify with `smbclient --version` that the patched package version is installed.

## Build
```
docker build -f scenario-08/Dockerfile -t meta3u-s08 .
docker run -d --name meta3u-s08 -p 4445:445 meta3u-s08
docker exec meta3u-s08 /bin/bash /verify.sh
docker stop meta3u-s08 && docker rm meta3u-s08
```
