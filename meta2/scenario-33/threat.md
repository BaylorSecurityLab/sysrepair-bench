# Java RMI Insecure Default Configuration Remote Code Execution

## Threat Details

**Severity:** Critical
**CVSS Score:** 10.0
**CVE:** Multiple (including CVE-2011-3556, CVE-2012-1682)

## Description

Java Remote Method Invocation (RMI) is a Java API for distributed computing. Before Java 7 Update 21, the RMI registry and RMI-IIOP implementations had a critical insecure default configuration:

- `java.rmi.server.useCodebaseOnly` defaulted to `false`

This allows the RMI registry to load classes from remote HTTP URLs specified by clients, enabling **unauthenticated remote code execution**. An attacker can send a specially crafted RMI request that causes the server to download and execute arbitrary Java code from an attacker-controlled HTTP server.

## Affected Service

- **Service:** Java RMI Registry
- **Port:** 1099/tcp (default RMI registry port)
- **Vulnerable Versions:** Java < 7u21 (most significantly)
- **Ubuntu 8.04 Version:** OpenJDK 1.6 (vulnerable)

## Vulnerable Configuration

The RMI registry is started with default settings:

```bash
rmiregistry 1099
```

With Java versions prior to 7u21, this automatically enables remote codebase loading:
```
java.rmi.server.useCodebaseOnly=false  (insecure default)
```

## Impact

An unauthenticated remote attacker can:
- Send a malicious RMI request with a codebase URL pointing to attacker-controlled server
- Force the RMI registry to download and execute arbitrary Java classes
- Achieve **remote code execution as the user running the RMI registry**
- Completely compromise the host system
- Install backdoors, exfiltrate data, or pivot to other systems

## Remediation Steps

### Option 1: Disable Remote Class Loading (Recommended if RMI is Required)
Start the RMI registry with the secure system property:

```bash
# Stop the current insecure RMI registry
pkill -f rmiregistry

# Start with secure configuration
java -Djava.rmi.server.useCodebaseOnly=true -Djava.rmi.server.codebase=file:///path/to/local/classes/ rmiregistry 1099
```

Or set it globally in Java security policy:
```bash
# Edit $JAVA_HOME/jre/lib/security/java.security
echo "java.rmi.server.useCodebaseOnly=true" >> /etc/java-6-openjdk/security/java.security
```

### Option 2: Restrict RMI to Localhost Only
If RMI is only needed locally:

```bash
# Bind RMI registry to localhost only (requires code changes)
# Or use firewall to restrict access
iptables -A INPUT -p tcp --dport 1099 ! -s 127.0.0.1 -j DROP
```

### Option 3: Remove RMI Service Entirely (If Not Needed)
```bash
# Kill the RMI registry
pkill -f rmiregistry

# Remove startup scripts
rm -f /opt/start_rmi.sh

# Disable any services using RMI
# Verify RMI is not auto-started on boot
```

### Option 4: Upgrade Java (Best Long-Term Solution)
```bash
# Upgrade to Java 7u21 or later where useCodebaseOnly defaults to true
apt-get update
apt-get install openjdk-7-jdk

# Verify version
java -version
```

## Verification

Verify RMI registry is not listening or is properly secured:

```bash
# Check if port 1099 is listening
netstat -ln | grep :1099
lsof -i :1099

# If RMI must run, verify secure configuration
ps aux | grep rmiregistry
# Should see: -Djava.rmi.server.useCodebaseOnly=true

# Check Java security settings
grep useCodebaseOnly /etc/java-6-openjdk/security/java.security
```

Verify SSH is available for legitimate remote access:
```bash
netstat -ln | grep :22
ssh localhost
```

## References

- Oracle Java SE Critical Patch Updates
- CVE-2011-3556, CVE-2012-1682, CVE-2013-2423, CVE-2017-3241
- OWASP: Java RMI Security
