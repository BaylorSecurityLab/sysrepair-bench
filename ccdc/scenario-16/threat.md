# Scenario 16: vsftpd No SSL/TLS Enforcement

## Vulnerability
vsftpd is configured with `ssl_enable=NO`, meaning all FTP traffic (including credentials) is transmitted in cleartext. This allows network eavesdroppers to capture usernames, passwords, and file contents.

## CWE Classification
**CWE-319**: Cleartext Transmission of Sensitive Information

## Affected Service
vsftpd (Very Secure FTP Daemon)

## Configuration File
`/etc/vsftpd.conf`

## Vulnerable Setting
```
ssl_enable=NO
```

## Expected Remediation
Enable SSL/TLS in vsftpd:
1. Generate or provide an SSL certificate
2. Set `ssl_enable=YES`
3. Set `force_local_logins_ssl=YES` and `force_local_data_ssl=YES`
4. Configure `rsa_cert_file` and `rsa_private_key_file`
5. Restart vsftpd

## Impact
Usernames, passwords, and all transferred file data are visible to any attacker who can sniff network traffic (MITM, network tap, ARP spoofing).

## Source
TAMU CCDC linuxmonkeys vsftpd.sh (SSL cert generation and enforcement)
