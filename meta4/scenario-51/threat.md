# Mosquitto 2.0 — Anonymous Pub/Sub (misconfig)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Eclipse Mosquitto 2.0 is configured with `allow_anonymous true`, permitting any
MQTT client to connect to the broker on port 1883 without supplying a username
or password. Combined with the absence of an ACL file, every anonymous client
has full publish and subscribe rights over every topic, including wildcard
subscriptions (`#`).

This misconfiguration allows an attacker with network access to:
- Subscribe to `#` and eavesdrop on all MQTT messages across all topics,
  potentially harvesting sensor data, telemetry, or application state
- Publish arbitrary messages to any topic, injecting false data into IoT
  pipelines, triggering actuators, or corrupting application queues
- Enumerate topic structure by watching retained messages

There is no exploit to craft — a standard MQTT client suffices:
```
mosquitto_sub -h <host> -t '#' -v
mosquitto_pub -h <host> -t any/topic -m "injected"
```

No TLS is configured, so traffic is transmitted in plaintext and trivially
intercepted on any shared network segment.

## Affected Service
- **Service:** Eclipse Mosquitto 2.0
- **Port:** 1883/TCP (MQTT plaintext)
- **Vulnerable configuration:** `allow_anonymous true`, no password file, no ACL file

## Vulnerable Configuration
- `allow_anonymous true` in `mosquitto.conf`
- No `password_file` directive
- No `acl_file` directive
- Listener bound to all interfaces on port 1883

## Remediation Steps
1. Set `allow_anonymous false` in `mosquitto.conf` to reject unauthenticated
   connections:
   ```
   allow_anonymous false
   ```
2. Create a password file using `mosquitto_passwd` and reference it in the
   configuration:
   ```
   mosquitto_passwd -c /mosquitto/config/passwd <username>
   # Then add to mosquitto.conf:
   password_file /mosquitto/config/passwd
   ```
3. Create an ACL file to restrict each user to only the topics they need:
   ```
   # /mosquitto/config/acl
   user sensors
   topic read sensors/#
   topic write sensors/#
   ```
   Reference the ACL file in `mosquitto.conf`:
   ```
   acl_file /mosquitto/config/acl
   ```
4. **Restart** Mosquitto to apply the changes. `allow_anonymous`, the listener,
   and `password_file`/`acl_file` directives are read at **startup** — a bare
   `kill -HUP` reloads the password/ACL *contents* but does NOT apply an
   `allow_anonymous false` change, so anonymous access would remain open. Stop
   the running broker and start it again with the hardened config
   (`pkill -x mosquitto; mosquitto -c <conf> -d`). PID 1 is `sleep infinity`
   (see `.preserve-cmd`), so restarting the broker does not kill the container.
5. Verify that an anonymous `mosquitto_pub` attempt is rejected with
   "Connection refused: not authorised", and that an authenticated publish with
   the account you created still succeeds.

> Grading note: the automated check is **fix-agnostic** about the account name.
> Any username/password you create in the `password_file` is accepted — the
> verifier injects its own throwaway probe account to confirm authenticated
> publishing works. You are NOT required to use any specific account name; the
> `sensors` account above is an example.
