# OPC-UA — SecurityPolicy=None (misconfig)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-319: Cleartext Transmission of Sensitive Information

## Category
Network Security

## Description
OPC Unified Architecture (OPC-UA) is the modern ICS/SCADA communication
standard used for data exchange between PLCs, SCADA systems, historians, and
HMIs. Unlike Modbus or S7comm, OPC-UA **does support security** — but it must
be explicitly configured.

When the server is started with `SecurityPolicy=None` and anonymous
authentication enabled:
- All OPC-UA traffic is transmitted in **cleartext** — readable by any
  network observer (credentials, process data, control commands)
- Any client can connect **without credentials** and browse the address space
- An attacker can read sensor values, write setpoints, invoke control methods,
  and subscribe to process data streams without authentication

This is a misconfiguration rather than a protocol design flaw — OPC-UA
provides strong security mechanisms (X.509 certificates, AES-256 encryption,
HMAC-SHA256 signatures) that the operator has failed to enable.

## Affected Service
- **Service:** OPC-UA server (python-opcua)
- **Port:** 4840/TCP
- **Vulnerable configuration:** SecurityPolicy=None, Anonymous auth enabled

## Remediation Steps
1. Remove `NoSecurity` / `SecurityPolicyType.NoSecurity` from the server's
   security policy list:
   ```python
   server.set_security_policy([SecurityPolicyType.Basic256Sha256])
   ```
2. Disable anonymous authentication and require username/password or
   certificate-based authentication:
   ```python
   server.set_security_IDs(["Username"])
   ```
3. Generate and install X.509 certificates for both the server and all
   authorized clients. Configure the server to reject connections from
   clients with untrusted certificates.
4. Verify that the OPC-UA Discovery Server does not advertise
   `SecurityPolicy=None` endpoints to clients.
