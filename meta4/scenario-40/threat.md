# MongoDB — Zlib Compression Amplification Risk (misconfiguration)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CVE: — (misconfiguration, no assigned CVE)
- CWE-400: Uncontrolled Resource Consumption
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Description
MongoDB 4.4 accepts zlib wire-protocol compression by default
(`net.compression.compressors: zlib`). When an unauthenticated client
negotiates zlib compression on the wire, two risks arise:

1. **Payload amplification.** A small compressed request can expand into a
   much larger BSON document inside the server process, consuming excess CPU
   and memory — a vector for resource-exhaustion against lightly resourced
   instances.

2. **Compression side-channel.** Shared-memory server processes that handle
   both attacker-controlled and victim data while zlib is active can leak
   information through compression ratio differences, analogous to CRIME/BREACH
   attacks on TLS-compressed HTTP.

Both risks are eliminated by removing `zlib` from the accepted compressor list.
The safer alternatives (`snappy`, `zstd`) do not exhibit the same amplification
or side-channel properties.

## Affected Service
- **Service:** MongoDB 4.4
- **Port:** 27017/TCP
- **Vulnerable configuration:** `net.compression.compressors` includes `zlib`

## Vulnerable Configuration
- `mongod.conf` contains `compressors: zlib` (or `zlib,snappy,zstd`)
- No explicit exclusion of `zlib` from the compressor list

## Remediation Steps
1. Edit `/etc/mongod/mongod.conf` (or the config file passed via `--config`)
   and set the compressors list to exclude `zlib`:
   ```yaml
   net:
     compression:
       compressors: snappy,zstd
   ```
   To disable all wire compression entirely, use:
   ```yaml
   net:
     compression:
       compressors: disabled
   ```
2. Restart `mongod` to apply the new configuration.
3. If clients negotiate compression on connect, update their connection
   strings to omit `compressors=zlib` (e.g., use `compressors=snappy`).
4. Confirm the fix by checking the running config:
   ```
   mongosh --eval "db.adminCommand({getCmdLineOpts:1})" | grep -i compressor
   ```
   The output must not contain `zlib`.
