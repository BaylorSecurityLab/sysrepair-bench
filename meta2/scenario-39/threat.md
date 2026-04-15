# Ubuntu 8.04 End-of-Life — Compensating Control (Host Firewall Lockdown)

## Severity
**High** — no upstream security patches available

## Category
Compensating Controls (the host cannot be upgraded without breaking the application
stack; mitigation must reduce the host's exposed surface without reinstalling the OS)

## Description
Ubuntu 8.04 LTS reached end-of-life in 2013; the base image receives no security patches.
Dozens of CVEs in the kernel, OpenSSL, glibc, and core services are unaddressable by
package updates. The compensating-control task is to enforce a **default-deny host
firewall** that leaves only the management channel (SSH/22) reachable, plus loopback,
shrinking the network attack surface even though the binaries themselves remain
unpatched.

## Remediation (compensating control)
```bash
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

Verify:
- `iptables -S` shows `-P INPUT DROP`.
- `iptables -S` contains an explicit accept for port 22.
- `sshd` still listening on 22.

## Out of Scope
- Upgrading to a supported Ubuntu release (breaks the application stack by design).
- Kernel live-patching (unavailable for Hardy).
