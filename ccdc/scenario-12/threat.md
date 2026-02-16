# Scenario 12: MySQL local-infile Enabled

## Vulnerability
MySQL is configured with `local-infile = 1`, which allows the `LOAD DATA LOCAL INFILE` statement. This can be exploited to read arbitrary files from the MySQL server's filesystem, potentially exposing sensitive data like `/etc/passwd`, `/etc/shadow`, or application configuration files.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
MySQL Server

## Configuration File
`/etc/mysql/mysql.conf.d/zzz-vulnerable.cnf` or `/etc/mysql/my.cnf`

## Vulnerable Setting
```
[mysqld]
local-infile = 1
[mysql]
local-infile = 1
```

## Expected Remediation
Set `local-infile = 0` in both the `[mysqld]` and `[mysql]` sections of the MySQL configuration and restart MySQL.

## Impact
An attacker with MySQL access can use `LOAD DATA LOCAL INFILE '/etc/shadow'` to read arbitrary files from the server filesystem, potentially obtaining password hashes and other sensitive data.

## Source
TAMU CCDC linuxmonkeys harden_mysql.sh (local-infile=0)
