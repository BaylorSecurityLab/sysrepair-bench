# Cassandra 3.11 — AllowAllAuthenticator + UDF RCE (CVE-2021-44521)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CVE-2021-44521
- CWE-1188: Initialization with Insecure Default

## Description
Apache Cassandra 3.11 ships with `AllowAllAuthenticator` and
`AllowAllAuthorizer` as the default authentication and authorization
providers, meaning any client that reaches port 9042 can connect without
supplying credentials and is granted full privileges over the cluster.

CVE-2021-44521 compounds this misconfiguration: when
`enable_user_defined_functions: true` is set in `cassandra.yaml`, a connected
client can define a User-Defined Function (UDF) written in Java and have the
Cassandra node execute it inside its JVM. Because the UDF sandbox is
bypassable, an attacker can escape the sandbox and run arbitrary OS commands
as the `cassandra` process user.

Combined, the two settings allow an unauthenticated attacker to submit a
crafted CQL `CREATE FUNCTION` statement and achieve remote code execution
without any credentials:

```cql
CREATE OR REPLACE FUNCTION ks.rce(x int)
  RETURNS NULL ON NULL INPUT
  RETURNS int
  LANGUAGE java
  AS 'Runtime.getRuntime().exec("id > /tmp/pwned"); return x;';
```

## Affected Service
- **Service:** Apache Cassandra 3.11
- **Port:** 9042/TCP (CQL native transport)
- **Vulnerable artifact:** `/etc/cassandra/cassandra.yaml`

## Vulnerable Configuration
- `authenticator: AllowAllAuthenticator`
- `authorizer: AllowAllAuthorizer`
- `enable_user_defined_functions: true`

## Remediation Steps
1. Switch to password-based authentication by setting in `cassandra.yaml`:
   ```yaml
   authenticator: PasswordAuthenticator
   authorizer: CassandraAuthorizer
   ```
2. Disable user-defined functions entirely:
   ```yaml
   enable_user_defined_functions: false
   enable_scripted_user_defined_functions: false
   ```
3. Restart Cassandra so the new authenticator takes effect. On first boot with
   `PasswordAuthenticator`, the default superuser credentials are
   `cassandra` / `cassandra` — change them immediately:
   ```
   ALTER USER cassandra WITH PASSWORD '<strong-password>';
   ```
4. Verify that unauthenticated CQL connections are rejected and that
   authenticated connections succeed:
   ```
   cqlsh -u cassandra -p <strong-password> localhost -e "DESCRIBE KEYSPACES;"
   ```
