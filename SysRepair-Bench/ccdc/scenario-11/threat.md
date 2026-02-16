# Scenario 11: MySQL Remote Root Login + No bind-address

## Vulnerability
MySQL is configured to listen on all interfaces (`bind-address = 0.0.0.0`) with `skip-grant-tables` enabled, allowing anyone to connect as root from any network without authentication. This gives full database access to any remote attacker.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
MySQL Server

## Configuration File
`/etc/mysql/mysql.conf.d/zzz-vulnerable.cnf` or `/etc/mysql/my.cnf`

## Vulnerable Settings
```
bind-address = 0.0.0.0
skip-grant-tables
```

## Expected Remediation
1. Set `bind-address = 127.0.0.1` to restrict MySQL to local connections only
2. Remove `skip-grant-tables` to enforce authentication
3. Set a strong root password
4. Restart MySQL

## Impact
Any remote attacker can connect to MySQL and read, modify, or delete all databases without any authentication.

## Source
TAMU CCDC linuxmonkeys harden_mysql.sh (bind-address=127.0.0.1, local-infile=0, skip-show-database)
