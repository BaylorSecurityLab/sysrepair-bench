# FTP Anonymous Login

## Severity
**Medium** (CVSS 6.4)

## CVE
CVE-1999-0497

## Description
The FTP server (vsftpd) on this system is configured to allow anonymous login. Anonymous
FTP access permits any user to connect to the FTP service without providing valid
credentials, using the username "anonymous" or "ftp" with any (or no) password.

This vulnerability is a well-known misconfiguration that has been assigned CVE-1999-0497.
While anonymous FTP was historically used for public file sharing, it presents serious
security risks in production environments:

- **Information disclosure:** Attackers can browse and download files from the FTP server
  without authentication, potentially accessing sensitive configuration files, backups,
  or application data.
- **Upload abuse:** If write access is also enabled for anonymous users, attackers can
  upload malicious files, use the server for warez distribution, or stage further attacks.
- **Reconnaissance:** Anonymous FTP access allows attackers to enumerate the server's
  directory structure and identify other attack vectors.

## Affected Service
- **Service:** vsftpd (Very Secure FTP Daemon)
- **Port:** 21/TCP
- **Binary:** /usr/sbin/vsftpd
- **Configuration:** /etc/vsftpd.conf

## Vulnerable Configuration
```
# /etc/vsftpd.conf
anonymous_enable=YES
```

## Remediation Steps
1. Edit `/etc/vsftpd.conf` and disable anonymous access:
   ```
   anonymous_enable=NO
   ```
2. Restart the vsftpd service:
   ```
   /etc/init.d/vsftpd restart
   ```
3. Verify by attempting to connect with anonymous credentials — the connection should
   be rejected.
4. Ensure local user access still works for legitimate FTP users.
