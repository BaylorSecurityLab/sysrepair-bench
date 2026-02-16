# rlogin Passwordless/Unencrypted Service Vulnerability

## Threat Details

**Severity:** High
**CVSS Score:** 7.5
**CVE:** CVE-1999-0651

## Description

The rlogin (remote login) service is a legacy BSD remote access protocol that suffers from multiple critical security flaws:

1. **No Encryption**: All traffic including authentication credentials is transmitted in cleartext
2. **Weak Authentication**: Relies on `.rhosts` and `/etc/hosts.equiv` files for trust-based authentication
3. **Passwordless Login**: Can allow access without any password if trust relationships are configured
4. **Host-Based Authentication**: Trusts the client-provided hostname without cryptographic verification

## Affected Service

- **Service:** rlogind (Remote Login Daemon)
- **Port:** 513/tcp
- **Protocol:** rlogin (unencrypted, obsolete)

## Vulnerable Configuration

The rlogin service is enabled in xinetd with a dangerous `/etc/hosts.equiv` configuration:

```
/etc/hosts.equiv:
+ +
```

This configuration allows **ANY user from ANY host** to login without a password.

## Impact

An attacker can:
- Login to the system without any password from any machine
- Intercept all rlogin traffic including credentials using network sniffing
- Spoof trusted hostnames to gain unauthorized access
- Execute arbitrary commands remotely
- Achieve complete system compromise through unauthenticated root access

This is one of the most severe misconfigurations possible on a Unix system.

## Remediation Steps

### Option 1: Remove rsh-server Entirely (Strongly Recommended)
```bash
# Stop xinetd
service xinetd stop

# Remove the rsh-server package
apt-get remove --purge rsh-server rsh-client

# Remove trust files
rm -f /etc/hosts.equiv
find /home -name .rhosts -delete
find /root -name .rhosts -delete

# Ensure SSH is available
apt-get install openssh-server
service ssh start
```

### Option 2: Disable rlogin in xinetd (If Package Must Remain)
```bash
# Disable rlogin, rsh, rexec services
for service in login shell exec; do
    sed -i 's/disable.*=.*no/disable = yes/' /etc/xinetd.d/r${service}
done

# Remove trust files
rm -f /etc/hosts.equiv
find /home -name .rhosts -delete

service xinetd restart
```

### Option 3: Block Port 513 with Firewall
```bash
iptables -A INPUT -p tcp --dport 513 -j DROP
iptables -A INPUT -p tcp --dport 514 -j DROP  # also block rsh
iptables-save > /etc/iptables/rules.v4
```

## Verification

Verify rlogin port is not accessible:
```bash
netstat -ln | grep :513
```

Verify rsh-server package is removed:
```bash
dpkg -l | grep rsh-server
```

Verify trust files are removed:
```bash
ls -la /etc/hosts.equiv
find / -name .rhosts 2>/dev/null
```

Verify SSH is available:
```bash
netstat -ln | grep :22
ssh localhost
```
