# Scenario 07: Apache Directory Listing Enabled

## Vulnerability
Apache is configured with `Options Indexes` enabled, which causes the server to display a listing of all files in a directory when no index file (index.html, index.php, etc.) is present. This exposes internal file structure and potentially sensitive files.

## CWE Classification
**CWE-548**: Exposure of Information Through Directory Listing

## Affected Service
Apache HTTP Server (apache2)

## Configuration File
`/etc/apache2/apache2.conf` or site-specific configs

## Vulnerable Setting
```
<Directory /var/www/>
    Options Indexes FollowSymLinks
</Directory>
```

## Expected Remediation
Change `Options Indexes` to `Options -Indexes` (disable Indexes) in all relevant Apache configuration blocks. Reload Apache.

## Impact
Directory listing exposes internal file names, backup files, configuration files, and other sensitive data that should not be publicly accessible.

## Source
TAMU CCDC linuxmonkeys apache.sh
