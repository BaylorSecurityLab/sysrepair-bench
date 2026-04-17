# CouchDB 3.2.1 — Default Erlang Cookie RCE (CVE-2022-24706)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-24706
- CWE-1188: Initialization with Insecure Default

## Description
Apache CouchDB is built on the Erlang/OTP runtime, which uses a shared secret
called the "Erlang cookie" to authenticate inter-node communication over the
Erlang distribution protocol. CouchDB 3.2.1 (and earlier releases) ship with
the default cookie value `monster` hard-coded in `/opt/couchdb/etc/vm.args`.

An attacker who knows this cookie can connect directly to the Erlang Port
Mapper Daemon (EPMD, default port 4369) and the corresponding distribution
port, then send arbitrary Erlang Remote Procedure Calls to the running node.
This gives unauthenticated remote code execution as the OS user running
CouchDB — no HTTP credentials, no CouchDB account, no exploit chain required.

A minimal attack using the `erl` client:

```
erl -name attacker@<host> -setcookie monster \
    -eval 'rpc:call(couchdb@<host>, os, cmd, ["id"])' \
    -noshell -s init stop
```

## Affected Service
- **Service:** Apache CouchDB 3.2.1
- **Port:** 5984/TCP (HTTP API), 4369/TCP (EPMD)
- **Vulnerable artifact:** `/opt/couchdb/etc/vm.args`

## Vulnerable Configuration
- `-setcookie monster` present in `vm.args`
- Erlang distribution port reachable from untrusted networks

## Remediation Steps
1. Replace the default cookie with a strong randomly generated value in
   `/opt/couchdb/etc/vm.args`:
   ```
   -setcookie $(openssl rand -hex 32)
   ```
   Write the generated value into `vm.args` — do not hard-code it in
   environment variables that may appear in process listings.
2. Restart CouchDB so the new cookie takes effect:
   ```
   supervisorctl restart couchdb
   ```
3. Block external access to the Erlang distribution ports using a firewall
   rule — EPMD and distribution ports must never be reachable from untrusted
   networks:
   ```
   iptables -A INPUT -p tcp --dport 4369 -j DROP
   iptables -A INPUT -p tcp --dport 9100:9200 -j DROP
   ```
4. Verify CouchDB is still operational via its HTTP API:
   ```
   curl http://localhost:5984/
   # expected: {"couchdb":"Welcome",...}
   ```
