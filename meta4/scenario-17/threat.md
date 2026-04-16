# PwnKit — polkit pkexec LPE (CVE-2021-4034)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2021-4034
- CWE-787: Out-of-bounds Write (argv[0] = NULL mishandling)

## Description
The setuid-root binary `/usr/bin/pkexec` (polkit ≤ 0.120) mishandles the
case where `argv[0]` is NULL. The argument parsing loop reads past the
end of `argv` into `envp`, allowing an unprivileged local user to
introduce an attacker-controlled environment variable (`GCONV_PATH`) into
the re-exec'd process and load a malicious shared library as root.

Public PoCs reliably yield a root shell in under a second on any
vulnerable system.

## Affected Service
- **Binary:** `/usr/bin/pkexec` (from `policykit-1 < 0.105-26ubuntu1.2`
  on Ubuntu 20.04, or upstream polkit ≤ 0.120)

## Remediation Steps
1. Upgrade `policykit-1` to **0.105-26ubuntu1.3** or later (or upstream
   polkit 0.121+). On Ubuntu 20.04:
   `apt-get update && apt-get install -y policykit-1`.
2. Stop-gap: remove the setuid bit with
   `chmod 0755 /usr/bin/pkexec`.
3. Regression: polkit is not required inside this container, but the
   binary must still exist on disk so that the remediation can be
   verified.
