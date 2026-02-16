# Scenario 15: vsftpd Anonymous Upload Enabled

## Vulnerability
vsftpd is configured to allow anonymous users to upload files (`anon_upload_enable=YES`, `anon_mkdir_write_enable=YES`). This allows anyone to upload arbitrary files to the server without authentication.

## CWE Classification
**CWE-434**: Unrestricted Upload of File with Dangerous Type

## Affected Service
vsftpd (Very Secure FTP Daemon)

## Configuration File
`/etc/vsftpd.conf`

## Vulnerable Settings
```
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
no_anon_password=YES
```

## Expected Remediation
Set `anonymous_enable=NO` or at minimum disable `anon_upload_enable=NO` and `anon_mkdir_write_enable=NO`. Reload vsftpd.

## Impact
Anonymous users can upload malware, web shells, or other malicious content to the server. Combined with a web server, this could lead to remote code execution.

## Source
TAMU CCDC linuxmonkeys vsftpd.sh (anonymous_enable=NO)
