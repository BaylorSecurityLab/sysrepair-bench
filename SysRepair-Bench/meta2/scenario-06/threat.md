# MySQL Root Empty Password

## Severity
**High** (CVSS 9.0)

## CVE
N/A (configuration weakness)

## Description
The MySQL database server on this system is configured with an empty password for the root
account and is listening on all network interfaces (0.0.0.0). This is a critical security
misconfiguration that replicates the Metasploitable 2 MySQL setup.

An attacker with network access to port 3306 can connect to the MySQL server as root without
any password, gaining full administrative control over all databases. This allows an attacker
to:

- **Read all data:** Access every database, table, and record on the server.
- **Modify data:** Insert, update, or delete any data, including user credentials.
- **Execute system commands:** Using MySQL features like `LOAD DATA INFILE`, `INTO OUTFILE`,
  or UDF (User Defined Functions) to read/write files or execute OS commands.
- **Escalate privileges:** Create new database users, grant privileges, or use MySQL
  as a pivot point for further attacks on the system.

## Affected Service
- **Service:** MySQL Server
- **Port:** 3306/TCP
- **Binary:** /usr/sbin/mysqld
- **Configuration:** /etc/mysql/my.cnf

## Vulnerable Configuration
```
# /etc/mysql/my.cnf
[mysqld]
bind-address = 0.0.0.0    # Listening on all interfaces

# MySQL root user has no password set
# mysql -u root (connects without password)
```

## Remediation Steps
1. Set a strong root password:
   ```
   mysql -u root -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('StrongP@ssw0rd!');"
   mysql -u root -p -e "SET PASSWORD FOR 'root'@'%' = PASSWORD('StrongP@ssw0rd!');"
   ```
2. Restrict MySQL to listen only on localhost by editing `/etc/mysql/my.cnf`:
   ```
   bind-address = 127.0.0.1
   ```
3. Remove remote root access:
   ```
   mysql -u root -p -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1');"
   mysql -u root -p -e "FLUSH PRIVILEGES;"
   ```
4. Restart MySQL:
   ```
   /etc/init.d/mysql restart
   ```
