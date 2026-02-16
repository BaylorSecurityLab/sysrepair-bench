# Telnet Service Running with Unencrypted Cleartext Login

## Threat Details

**Severity:** Medium
**CVSS Score:** 4.8
**CVE:** N/A (inherent protocol weakness)

## Description

Telnet is a legacy remote access protocol that transmits all data, including usernames and passwords, in cleartext over the network. Unlike SSH, Telnet provides no encryption, making it trivial for attackers to intercept credentials and session data through network sniffing.

## Affected Service

- **Service:** telnetd (Telnet Daemon)
- **Port:** 23/tcp
- **Protocol:** Telnet (unencrypted)

## Vulnerable Configuration

The telnet service is enabled in xinetd:

```
/etc/xinetd.d/telnet:
disable = no
```

All authentication credentials and session traffic are transmitted without encryption.

## Impact

An attacker with network access can:
- Intercept login credentials in cleartext using packet sniffers (tcpdump, Wireshark)
- Capture entire telnet sessions including all commands executed
- Conduct man-in-the-middle attacks to modify commands in transit
- Gain unauthorized access using stolen credentials
- Compromise the entire system through captured root/admin sessions

## Remediation Steps

### Option 1: Disable Telnet and Use SSH (Recommended)
```bash
# Stop and disable telnet
update-rc.d -f xinetd remove

# Or disable just telnet in xinetd
sed -i 's/disable = no/disable = yes/' /etc/xinetd.d/telnet
service xinetd restart

# Verify SSH is running
service ssh start
update-rc.d ssh defaults
```

### Option 2: Remove Telnet Package Entirely
```bash
apt-get remove --purge telnetd xinetd
apt-get install openssh-server
```

### Option 3: Block Port 23 with Firewall
```bash
iptables -A INPUT -p tcp --dport 23 -j DROP
iptables-save > /etc/iptables/rules.v4
```

## Verification

Verify telnet port is closed:
```bash
netstat -ln | grep :23
```

Verify SSH is available as replacement:
```bash
netstat -ln | grep :22
ssh localhost
```

Check xinetd status:
```bash
service xinetd status
grep disable /etc/xinetd.d/telnet
```
