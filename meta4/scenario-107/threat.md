# Erlang/OTP SSH Pre-auth RCE (CVE-2025-32433)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2025-32433
- CWE-306: Missing Authentication for Critical Function

## Description
Erlang/OTP's built-in SSH server implementation contains a critical flaw in
the handling of connection protocol messages. An attacker can send SSH
connection protocol messages — which are supposed to be processed only after
authentication — prior to completing authentication. This allows the attacker
to reach server-side channel handlers and execute arbitrary code on the host
without valid credentials.

Any Erlang application that uses the `ssh:daemon/2,3` function is potentially
affected, including distributed Erlang nodes, RabbitMQ, and CouchDB
deployments that expose the OTP SSH port.

The Erlang SSH daemon typically runs on a non-standard port (e.g. 2222) rather
than the system SSH port (22).

## Affected Service
- **Service:** Erlang/OTP SSH daemon (`ssh:daemon/2`)
- **Port:** 2222/TCP (OTP SSH — NOT the OS ssh on 22)
- **Vulnerable versions:** OTP ≤ 27.3.2, 26.x ≤ 26.2.5.11, 25.x ≤ 25.3.2.20

## Vulnerable Configuration
The `ssh:daemon(2222, [...])` call is reachable from any IP — no network-level
restriction is in place to limit who can initiate an SSH handshake.

## Remediation (Compensating Control)
**Do NOT rely solely on upgrading** when an immediate OTP upgrade is not
feasible. Apply the following compensating controls:

1. **iptables DROP rule** — block inbound connections to the OTP SSH port
   (2222) from all sources except trusted admin IP ranges:
   ```bash
   iptables -I INPUT -p tcp --dport 2222 -j DROP
   # Allow only trusted admin subnet:
   iptables -I INPUT -p tcp -s 10.0.0.0/8 --dport 2222 -j ACCEPT
   ```

2. **Disable the OTP SSH daemon** entirely if it is not required for the
   application's operation. Remove the `ssh:daemon(...)` call or add an
   application configuration guard.

3. Combine both controls: restrict network access AND disable the daemon
   if not needed.
