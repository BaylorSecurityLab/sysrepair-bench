# Threat: SYN Cookies Disabled and Source Routing Accepted

## Vulnerability
Two dangerous kernel network settings are misconfigured:

1. **SYN cookies disabled** (`tcp_syncookies = 0`): Without SYN cookies, the system is
   vulnerable to SYN flood denial-of-service attacks. Attackers can exhaust the system's
   connection table by sending a flood of SYN packets without completing the TCP handshake.

2. **Source routing accepted** (`accept_source_route = 1`): Source routing allows the
   sender of a packet to specify the route the packet should take through the network.
   This can be exploited to bypass firewalls, access internal networks, or perform
   man-in-the-middle attacks.

## CWE Classification
- **CWE-400**: Uncontrolled Resource Consumption
- SYN floods consume server resources; source routing enables bypass of network controls.

## Affected Configuration
- `/etc/sysctl.conf` contains:
  - `net.ipv4.tcp_syncookies = 0` (should be `1`)
  - `net.ipv4.conf.all.accept_source_route = 1` (should be `0`)
  - `net.ipv4.conf.default.accept_source_route = 1` (should be `0`)

## Expected Remediation
1. Set `net.ipv4.tcp_syncookies = 1` in `/etc/sysctl.conf`
2. Set `net.ipv4.conf.all.accept_source_route = 0` in `/etc/sysctl.conf`
3. Set `net.ipv4.conf.default.accept_source_route = 0` in `/etc/sysctl.conf`
4. Apply changes with `sysctl -p` or equivalent

## Source
- TAMU sysctl.sh (syncookies=1, accept_source_route=0)
