# FTP Unencrypted Cleartext Login

## Severity
**Medium** (CVSS 4.8)

## CVE
N/A (protocol/configuration weakness)

## Description
The FTP server (vsftpd) on this system transmits all data, including user credentials,
in cleartext over the network. The FTP protocol (RFC 959) was designed without built-in
encryption, meaning that usernames, passwords, and file contents are sent as plaintext.

Without SSL/TLS encryption (FTPS), an attacker on the same network segment can trivially
capture FTP credentials using passive network sniffing tools such as tcpdump, Wireshark,
or ettercap. This is especially dangerous in shared network environments, wireless networks,
or any scenario where an attacker can perform ARP spoofing or traffic interception.

The captured credentials can then be used to:
- Access the FTP server with the victim's privileges
- Pivot to other services if the user reuses passwords
- Download or tamper with sensitive files

## Affected Service
- **Service:** vsftpd (Very Secure FTP Daemon)
- **Port:** 21/TCP
- **Binary:** /usr/sbin/vsftpd
- **Configuration:** /etc/vsftpd.conf

## Vulnerable Configuration
```
# /etc/vsftpd.conf
# ssl_enable is not set (defaults to NO)
# No TLS/SSL configuration present
# All FTP traffic is transmitted in cleartext
```

## Remediation Steps
1. Generate a self-signed SSL certificate (or use a CA-signed certificate):
   ```
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout /etc/ssl/private/vsftpd.key \
       -out /etc/ssl/certs/vsftpd.crt \
       -subj "/CN=ftpserver"
   ```
2. Edit `/etc/vsftpd.conf` and add SSL/TLS configuration:
   ```
   ssl_enable=YES
   force_local_logins_ssl=YES
   force_local_data_ssl=YES
   rsa_cert_file=/etc/ssl/certs/vsftpd.crt
   rsa_private_key_file=/etc/ssl/private/vsftpd.key
   ```
3. Restart the vsftpd service:
   ```
   /etc/init.d/vsftpd restart
   ```
4. Verify that FTP clients are now required to use TLS for authentication.
