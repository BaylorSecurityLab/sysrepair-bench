# VNC Exposed on All Interfaces — Compensating Control (bind-localhost + SSH tunnel)

## Severity
**High** — CVSS 9.0 (weak/guessable password, cleartext transport)

## Category
Compensating Controls (administrative VNC access must remain available to remote admins,
but direct exposure to untrusted networks must be eliminated)

## Description
The VNC server listens on `0.0.0.0:5900` with a short password and no transport encryption.
A full fix (kill VNC, replace with RDP-over-TLS) is out of scope for this host. The
compensating-control task is to:

1. Bind VNC to `127.0.0.1` only.
2. Require admins to reach it via SSH tunnel: `ssh -L 5900:127.0.0.1:5900 root@host`.
3. Mark the state file `/root/.vnc/bound-local` so the startup script respects the
   new policy on reboot.

## Remediation (compensating control)
```bash
touch /root/.vnc/bound-local
vncserver -kill :0 2>/dev/null || true
pkill -f 'nc -l -p 5900'
vncserver :0 -interface 127.0.0.1 -geometry 1024x768
```

Verify:
- `netstat -tlnp | grep :5900` shows `127.0.0.1:5900`, not `0.0.0.0:5900`.
- sshd still listens on 22 so the admin's SSH tunnel still works.

## Out of Scope
- Replacing VNC with another remote-desktop stack.
- Raising VNC password strength / adding TLS (separate scenarios S08/S09 cover auth).
