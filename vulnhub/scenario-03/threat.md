# MySQL No secure_file_priv - OUTFILE Exploit

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
MySQL/MariaDB is configured with an empty `secure_file_priv` directive, allowing the
database to read and write files to any directory on the filesystem. Combined with a
database user having the FILE privilege, an attacker can use `SELECT ... INTO OUTFILE`
to write arbitrary files (such as webshells) or `LOAD DATA INFILE` to read sensitive
system files.

This mirrors the Kioptrix Level 1.3 (Level 4) VulnHub VM with vulnerable MySQL OUTFILE
configurations.

## Affected Service
- **Service:** MariaDB/MySQL
- **Port:** 3306/TCP
- **Configuration:** /etc/mysql/mariadb.conf.d/99-vulnerable.cnf

## Vulnerable Configuration
```
[mysqld]
secure_file_priv=
```

## Remediation Steps
1. Set `secure_file_priv` to a restricted directory in MariaDB config:
   ```
   [mysqld]
   secure_file_priv=/var/lib/mysql-files/
   ```
2. Create the restricted directory: `mkdir -p /var/lib/mysql-files && chown mysql:mysql /var/lib/mysql-files`
3. Revoke FILE privilege from web user: `REVOKE FILE ON *.* FROM 'webuser'@'localhost';`
4. Restart MariaDB: `service mysql restart`
