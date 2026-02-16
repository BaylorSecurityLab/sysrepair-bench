# SSH Default Credentials

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness / default credentials)

## Description
The SSH server on this system has multiple user accounts configured with weak, default, or
easily guessable passwords. This is a direct replica of the Metasploitable 2 configuration
where several accounts use the username as the password:

- **msfadmin:msfadmin** — The primary administrative account uses its own name as password.
- **user:user** — A standard user account with a trivially guessable password.
- **root:root** — The root account itself has a default password.

Combined with `PasswordAuthentication yes` in the SSH configuration, these accounts are
trivially compromised via brute-force or credential-stuffing attacks. An attacker with
network access to port 22 can gain full shell access to the system within seconds.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
- **Binary:** /usr/sbin/sshd
- **Configuration:** /etc/ssh/sshd_config
- **Affected accounts:** root, msfadmin, user

## Vulnerable Configuration
```
# /etc/ssh/sshd_config
PasswordAuthentication yes
PermitRootLogin yes

# /etc/shadow (conceptual)
# msfadmin password = "msfadmin"
# user password = "user"
# root password = "root"
```

## Remediation Steps
1. Change all weak passwords to strong, random values:
   ```
   passwd root        # Set a strong password (16+ chars, mixed case, numbers, symbols)
   passwd msfadmin    # Set a strong password
   passwd user        # Set a strong password
   ```
2. Alternatively, disable password authentication entirely and use SSH keys:
   ```
   # In /etc/ssh/sshd_config:
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```
3. If password authentication must remain enabled, consider installing fail2ban or
   equivalent to throttle brute-force attempts.
4. Restart the SSH daemon:
   ```
   /etc/init.d/ssh restart
   ```
