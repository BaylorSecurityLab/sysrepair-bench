# MongoDB 4.4.29 — MongoBleed Memory Disclosure (CVE-2025-14847)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CVE-2025-14847 (MongoBleed)
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Description
MongoDB 4.4.29 accepts zlib wire-protocol compression by default
(`net.compression.compressors: zlib`). CVE-2025-14847, dubbed "MongoBleed",
exploits a flaw in the server's zlib decompression path: a specially crafted
compressed message with a manipulated header causes MongoDB to read beyond
the intended buffer boundary. The server then echoes the out-of-bounds heap
memory back to the caller inside the error or response frame.

Because the vulnerable path is reached before authentication is checked, an
unauthenticated attacker on the network can send a single malformed packet to
port 27017 and receive a response containing arbitrary heap contents —
potentially including in-flight credentials, session tokens, cached query
results, or internal bookkeeping structures.

The attack does not require a valid MongoDB client and is trivially
scriptable using raw TCP with a hand-crafted OP_COMPRESSED message:

```
<OP_COMPRESSED header> compressorId=1 (zlib) originalOpCode=<any>
<intentionally truncated / oversized uncompressedSize field>
```

## Affected Service
- **Service:** MongoDB 4.4.29
- **Port:** 27017/TCP
- **Vulnerable configuration:** `net.compression.compressors` includes `zlib`

## Vulnerable Configuration
- `mongod.conf` contains `compressors: zlib` (or `zlib,snappy,zstd`)
- No explicit `compressors: none` or exclusion of `zlib` from the list

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
