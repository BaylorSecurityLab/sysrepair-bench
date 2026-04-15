# Java RMI Registry + DistCC Open to Internet — Compensating Control

## Severity
**Critical** — CVSS 10.0 (Java RMI CVE-2011-3556 class-loader RCE) / 9.3 (DistCC CVE-2004-2687)

## Category
Compensating Controls (both services must remain reachable *internally* for the
build-farm / JVM orchestration that depends on them, but exposure to untrusted networks
must be eliminated)

## Description
DistCC (3632) is configured with `--allow 0.0.0.0/0`, exposing the fork-and-exec build
helper to the Internet; Java RMI registry (1099) is similarly bound to all interfaces,
allowing remote class loading. Removing these services would break the build pipeline and
the management JVM. The compensating-control task is to:

1. Tighten DistCC's `--allow` to the trusted build subnet only (e.g., `10.10.0.0/24`).
2. Add an iptables default-deny on ports 1099 and 3632 with an explicit accept from the
   trusted subnet.

## Affected Ports
- 1099/TCP — Java RMI Registry
- 3632/TCP — DistCC daemon

## Remediation (compensating control)
```bash
# DistCC: restrict allowed clients
sed -i 's|ALLOWEDNETS=".*"|ALLOWEDNETS="10.10.0.0/24"|' /etc/default/distcc
pkill distccd
distccd --daemon --allow 10.10.0.0/24

# Firewall: default-deny 1099 and 3632, allow trusted subnet and loopback
iptables -A INPUT -i lo -p tcp -m multiport --dports 1099,3632 -j ACCEPT
iptables -A INPUT -s 10.10.0.0/24 -p tcp -m multiport --dports 1099,3632 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 1099,3632 -j DROP
```

Verify:
- `iptables -S` shows DROP rules on 1099 and 3632.
- DistCC config no longer contains `0.0.0.0/0` in ALLOWEDNETS.
- Services still listen locally (build server process health preserved).

## Out of Scope
- Removing DistCC or RMI (breaks build farm / JVM orchestration).
- Upgrading RMI to post-CVE JDK (out of reach on Ubuntu 8.04).
