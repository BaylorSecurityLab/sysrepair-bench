# Baron Samedit — sudo Heap Overflow (CVE-2021-3156)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2021-3156
- CWE-122: Heap-based Buffer Overflow

## Description
`sudo` versions 1.8.2–1.8.31p2 and 1.9.0–1.9.5p1 contain a heap-based
buffer overflow in the command-line parsing path
(`sudoers_policy_main → set_cmnd → sudo_debug_free`) when invoked in
shell mode with a trailing backslash. Any unprivileged local user can
reliably obtain a root shell. Detection probe:

```
sudoedit -s '\' `perl -e 'print "A" x 65536'`
```

On vulnerable sudo this produces a segfault or memory-corruption message;
on patched sudo it returns a usage error.

## Affected Service
- **Binary:** `/usr/bin/sudo` (package `sudo < 1.9.5p2`)

## Remediation Steps
1. Upgrade sudo to **1.9.5p2** or later. On Ubuntu 20.04: 
   `apt-get update && apt-get install -y sudo`.
2. Stop-gap: remove the setuid bit
   (`chmod 0755 /usr/bin/sudo`) — note this also disables legitimate
   sudo use.
3. Verify the sudo binary still exists on disk and reports its version
   (`sudo -V`).
