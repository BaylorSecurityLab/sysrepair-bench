# Kafka 3.5 — No SASL Authentication / No ACLs (misconfig)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Apache Kafka 3.5 ships with a `PLAINTEXT` listener and no authentication or
authorization configured by default. Any client with network access to port 9092
can produce messages to any topic, consume from any topic (including internal
topics such as `__consumer_offsets`), create and delete topics, and alter
partition assignments — all without supplying any credentials.

Combined with no ACL authorizer, there is no mechanism to distinguish legitimate
producers/consumers from malicious ones. An attacker can:
- Exfiltrate all messages by subscribing to every topic
- Inject malicious messages into any queue
- Disrupt processing by deleting or compacting topics
- Read `__consumer_offsets` to track consumer group progress and tamper with offsets

The attack requires only a standard Kafka client library:
```
kafka-console-consumer.sh --bootstrap-server <host>:9092 --topic <any-topic> --from-beginning
```

## Affected Service
- **Service:** Apache Kafka 3.5
- **Port:** 9092/TCP
- **Vulnerable configuration:** `PLAINTEXT` listener, no `sasl.enabled.mechanisms`, no `authorizer.class.name`

## Vulnerable Configuration
- `listeners=PLAINTEXT://:9092` — no SASL protocol
- `sasl.enabled.mechanisms` not set
- `authorizer.class.name` not set — all clients have full access
- `allow.everyone.if.no.acl.found=true` (effective default)

## Remediation Steps
1. Switch the listener protocol to `SASL_PLAINTEXT` (or `SASL_SSL`) in
   `server.properties`:
   ```
   listeners=SASL_PLAINTEXT://:9092
   advertised.listeners=SASL_PLAINTEXT://<hostname>:9092
   security.inter.broker.protocol=SASL_PLAINTEXT
   sasl.mechanism.inter.broker.protocol=PLAIN
   sasl.enabled.mechanisms=PLAIN
   ```
2. Create a JAAS configuration file (`kafka_server_jaas.conf`) and pass it
   to the broker via `KAFKA_OPTS`:
   ```
   KafkaServer {
     org.apache.kafka.common.security.plain.PlainLoginModule required
     username="admin"
     password="<strong-password>"
     user_admin="<strong-password>";
   };
   ```
3. Enable the ACL authorizer so that unauthenticated or unauthorized requests
   are denied:
   ```
   authorizer.class.name=kafka.security.authorizer.AclAuthorizer
   allow.everyone.if.no.acl.found=false
   super.users=User:admin
   ```
4. Grant producers and consumers explicit ACLs using `kafka-acls.sh` for each
   topic and consumer group they legitimately need.
5. Verify the broker still accepts connections on port 9092 with valid credentials
   after applying the changes.
