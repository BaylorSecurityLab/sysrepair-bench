# VNC Unencrypted Data Transmission

## Severity
**Medium** | CVSS 4.8

## CVE
N/A (configuration weakness)

## Description
The VNC (Virtual Network Computing) server is configured to accept connections without SSL/TLS encryption. VNC Security Type 1 (None) or Type 2 (VNC Authentication) transmit data in cleartext or with only a weak DES-based challenge-response for the password, while all subsequent session data (keystrokes, screen updates) travels unencrypted. An attacker on the network path can capture credentials and observe or inject input into the remote desktop session via passive sniffing or man-in-the-middle attacks.

## Affected Service
- **Service:** x11vnc (VNC server)
- **Port:** 5900/tcp
- **Protocol:** RFB (Remote Framebuffer)

## Vulnerable Configuration
The VNC server is started without any SSL/TLS wrapper:

```
x11vnc -display :0 -rfbport 5900 -rfbauth /root/.vnc/passwd -forever -shared
```

No `-ssl` or `-stunnel` flag is used, and the service is not tunneled through SSH. All RFB protocol traffic is transmitted in cleartext over the network.

## Remediation Steps
1. **Option A -- Enable SSL on x11vnc:**
   - Start x11vnc with the `-ssl` flag to enable built-in SSL/TLS encryption:
     ```
     x11vnc -display :0 -rfbport 5900 -rfbauth /root/.vnc/passwd -forever -shared -ssl SAVE
     ```
2. **Option B -- Tunnel VNC through SSH:**
   - Stop exposing port 5900 externally.
   - Connect to VNC only via SSH tunnel:
     ```
     ssh -L 5900:localhost:5900 user@host
     ```
3. **Option C -- Disable VNC entirely and use SSH X forwarding:**
   - Stop the VNC server process.
   - Remove or disable the VNC startup script.
   - Use `ssh -X` or `ssh -Y` for remote GUI access.
4. Restrict VNC access via firewall rules to trusted networks only.
