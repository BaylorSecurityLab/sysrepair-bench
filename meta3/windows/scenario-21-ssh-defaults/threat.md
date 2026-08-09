# OpenSSH-Win32 Legacy Build + Default `vagrant:vagrant` Admin Credentials

## Severity
**Critical** (CVSS 9.8 — unauthenticated-to-root/SYSTEM via guessable creds;
multiple unpatched pre-auth CVEs on the SSH server itself)

## CVE
OpenVAS flagged the following on this host's port 22, all traceable to the same
legacy Win32-OpenSSH 7.1.0.0-p1-beta binary Rapid7 ships:

- **CVE-2016-1908** — OpenSSH unauthenticated X11 forwarding trust bypass.
- **CVE-2016-6210** — OpenSSH user-enumeration via response-time oracle.
- **CVE-2016-6515** — OpenSSH pre-auth DoS via overlong password.
- **CVE-2016-10009 / 10010 / 10011 / 10012** — OpenSSH 7.3 privilege-separation and
  agent-forwarding issues.
- **CVE-2017-15906** — OpenSSH sftp-server read-only bypass (< 7.6).
- **CVE-2018-15473 / 15919** — OpenSSH 7.7 user enumeration.
- Additional user-enumeration and DoS variants up through the 2024/2025 lineage
  that stale Win32-OpenSSH has never received back-ported fixes for.

Independent of the CVEs, the **vagrant / vagrant** local administrator account —
installed by the Rapid7 provisioner and never rotated — grants full interactive and
network logon via this same SSH listener.

## Description
Rapid7's metasploitable3-windows Vagrant build installs the Microsoft
Win32-OpenSSH 7.1.0.0-beta release so Vagrant can drive provisioning. The account
it authenticates with is `vagrant:vagrant`, a local member of
`BUILTIN\Administrators`. Neither the binary nor the password is ever rotated for
the lifetime of the box.

An unauthenticated attacker who can reach port 22 has two independent paths to
SYSTEM-equivalent code execution:
1. `ssh vagrant@<host>` with password `vagrant` — immediate interactive shell as
   local admin; trivial privilege escalation to `NT AUTHORITY\SYSTEM` via
   `PsExec -s` or a quick `New-Service` drop.
2. Any of the pre-auth OpenSSH CVEs that a 7.1.0.0-beta build never received a
   patch for — most are DoS/enum, but the overall posture is that of an unsupported
   SSH daemon.

## Affected Service
- **Service:** `sshd` (Win32-OpenSSH 7.1.0.0-p1-beta)
- **Port:** 22/TCP
- **Binary path:** `C:\Program Files\OpenSSH\sshd.exe`
- **Credential:** `vagrant:vagrant` in `Administrators`

## Vulnerable Configuration
```
OpenSSH for Windows version : 7.1.0.0-p1-Beta (released 2015)
vagrant local user          : password = "vagrant", member of Administrators
sshd                        : LISTEN 0.0.0.0:22, password auth enabled
```

## Remediation Steps
The verifier grades three things independently, and all three must hold: the
password must no longer be the default, the `vagrant` account must no longer be
a local administrator, and the `sshd` service must launch a supported build.
Deleting the account satisfies the first two at once.

1. **Rotate the default password AND drop the account out of `Administrators`**
   (it was only ever needed for provisioning, so removing it outright is the
   cleaner fix):
   ```powershell
   $pw = Read-Host -AsSecureString 'new vagrant password'
   Set-LocalUser -Name 'vagrant' -Password $pw
   # Or remove it outright once provisioning is done:
   Remove-LocalGroupMember -Group 'Administrators' -Member 'vagrant' -ErrorAction SilentlyContinue
   Remove-LocalUser       -Name  'vagrant' -ErrorAction SilentlyContinue
   ```
2. **Replace the legacy OpenSSH binary** with a supported build (major ≥ 9).
   A fixed release is staged on the host at `C:\ossh-fixed.zip` — this container
   has no outbound network, so unpack that rather than trying to download one:
   ```powershell
   Stop-Service sshd
   Expand-Archive -Path 'C:\ossh-fixed.zip' -DestinationPath 'C:\Program Files\' -Force
   Remove-Item 'C:\Program Files\OpenSSH' -Recurse -Force
   Rename-Item 'C:\Program Files\OpenSSH-Win64' 'C:\Program Files\OpenSSH'
   Start-Service sshd
   ```
   Note `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` is NOT
   sufficient here: the inbox capability on Server 2019 is OpenSSH **7.7**, which
   is older than the CVE-2018-15473 fix line this scenario is about, so it does
   not satisfy the version requirement even though it "reinstalls OpenSSH".
3. **Disable password authentication** in favor of key-based auth (`sshd_config`:
   `PasswordAuthentication no`), and restrict the listener to a management
   interface rather than `0.0.0.0`.
