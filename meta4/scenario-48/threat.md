# ActiveMQ 5.17.6 — Unauthenticated OpenWire port 61616 exposed (compensating control)

## Severity
**High** (network exposure of an unauthenticated broker transport)

## CVE / CWE
- CWE-284: Improper Access Control
- Context: CVE-2023-46604 (OpenWire deserialization RCE)

## IMPORTANT — scenario scope
The pinned image `apache/activemq-classic:5.17.6` already contains the fix for
CVE-2023-46604 (the OpenWire deserialization RCE was patched in 5.17.6, 5.16.7
and 5.15.16). The shipped binary is `activemq-broker-5.17.6.jar`, so that
specific RCE is **not** present in this image. This scenario therefore grades the
genuine residual risk that remains on a patched broker: the unauthenticated
OpenWire transport on port 61616 is reachable from untrusted networks, which is
an access-control problem best addressed with a compensating control (host
firewall). Config knobs such as `SERIALIZABLE_PACKAGES` and `maxFrameSize` are
defense-in-depth for the *class* of deserialization bugs but do not, on their
own, remove the network exposure and are not what the behavioural check grades.

## Description
Apache ActiveMQ exposes the OpenWire wire protocol on port 61616. In the default
configuration this transport is reachable by any client on any network without
authentication. Even on a patched broker, an unauthenticated OpenWire endpoint
exposed to untrusted networks is a significant attack surface (message
injection/consumption, resource abuse, and exposure to any future protocol-level
vulnerability). The remediation is to restrict who can reach 61616.

## Affected Service
- **Service:** Apache ActiveMQ Classic 5.17.6
- **Port:** 61616/TCP (OpenWire)
- **Residual risk:** unauthenticated OpenWire transport reachable from untrusted networks

## Vulnerable Configuration
- Port 61616 accessible from untrusted networks (no host firewall restriction)

## Remediation Steps
1. Restrict access to port 61616 via a host firewall so only trusted broker IPs
   and application servers can reach the OpenWire port (this is the primary,
   behaviourally-graded control):
   ```
   iptables -I INPUT -p tcp --dport 61616 -s <trusted-cidr> -j ACCEPT
   iptables -I INPUT -p tcp --dport 61616 -j DROP
   ```
2. Keep the broker patched (5.17.6+) so the OpenWire deserialization RCE class
   (CVE-2023-46604) stays fixed.
3. Defense-in-depth: restrict deserialization to safe packages via
   `ACTIVEMQ_OPTS` (`-Dorg.apache.activemq.SERIALIZABLE_PACKAGES=...` in
   `/opt/apache-activemq/bin/env`) and set `wireFormat.maxFrameSize` on each
   transport connector in `conf/activemq.xml`.
4. Verify the web console on port 8161 still responds after applying the
   changes above, and that a TCP connect to 61616 is refused/blocked.
