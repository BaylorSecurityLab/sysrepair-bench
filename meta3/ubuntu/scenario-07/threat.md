# ProFTPD 1.3.5 mod_copy Arbitrary File Copy

## Severity
**Critical** (CVSS 10.0)

## CVE
CVE-2015-3306

## Description
ProFTPD 1.3.5 ships with `mod_copy` enabled by default. The `mod_copy` module
implements the `SITE CPFR` (copy from) and `SITE CPTO` (copy to) FTP commands,
which allow any unauthenticated client to read and write arbitrary files on the
server filesystem. Because ProFTPD runs as root or a service account with broad
filesystem access, an attacker can:

1. Copy `/etc/passwd` or SSH private keys to a web-accessible directory and
   retrieve them over HTTP.
2. Copy a PHP web shell into the web root and execute arbitrary commands.
3. Overwrite critical system files.

No authentication is required. The commands are processed in the pre-authentication
context of the FTP session.

## Affected Service
- **Service:** ProFTPD 1.3.5
- **Port:** 21/TCP
- **Binary:** /opt/proftpd/sbin/proftpd
- **Module:** mod_copy.so

## Proof of Concept
```
nc -n 127.0.0.1 21
# wait for banner, then send:
SITE CPFR /etc/passwd
# expect: 350 File or directory exists, ready for destination name
SITE CPTO /tmp/passwd.copy
# expect: 250 Copy successful
```
Any FTP client can issue these commands before authenticating.

## Vulnerable Configuration
ProFTPD 1.3.5 compiled with `--with-modules=mod_copy`. The module is active
by default once compiled in. No `LoadModule` directive is required; the module
is statically linked.

## Remediation Steps
1. Upgrade ProFTPD to version 1.3.5a or later (1.3.6+ preferred) which removes
   unauthenticated `mod_copy` access:
   ```
   apt-get install -y proftpd
   ```
   Or compile from source with a patched version:
   ```
   wget ftp://ftp.proftpd.org/distrib/source/proftpd-1.3.6.tar.gz
   tar xzf proftpd-1.3.6.tar.gz && cd proftpd-1.3.6
   ./configure --prefix=/opt/proftpd && make && make install
   ```
2. Restart ProFTPD:
   ```
   kill $(cat /var/run/proftpd/proftpd.pid) && /opt/proftpd/sbin/proftpd
   ```
3. Verify that `SITE CPFR /etc/passwd` returns a 500-series error or is unknown.

## Build
```
docker build -f scenario-07/Dockerfile -t meta3u-s07 .
docker run -d --name meta3u-s07 -p 2121:21 meta3u-s07
docker exec meta3u-s07 /bin/bash /verify.sh
docker stop meta3u-s07 && docker rm meta3u-s07
```
