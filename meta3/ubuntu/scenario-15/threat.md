# UnrealIRCd Version Pinned -- Bind 127.0.0.1, Front with stunnel (Compensating Control)

## Severity
**High** (CVSS 7.5) -- network exposure of a pinned legacy IRC daemon

## CVE / CWE
- CWE-668: Exposure of Resource to Wrong Sphere (bind to 0.0.0.0)
- Note: CVE-2010-2075 (UnrealIRCd backdoor) and CVE-2016-7144 (auth spoofing) are
  already covered by meta2/ scenarios. This scenario targets the network exposure
  surface only: the IRC daemon bound to all interfaces with no TLS gateway.

## Category
Compensating Control

## Constraint
**The UnrealIRCd version must not be changed.** Legacy IRC bots and scripts in the
environment depend on the specific version and protocol behaviour of the installed
Unreal3.2 build. The agent cannot upgrade, replace, or remove the daemon. The
compensating control is purely a network-layer measure: restrict the raw TCP
listener to loopback and present a TLS-wrapped port to trusted external clients
via stunnel.

## Description
UnrealIRCd is configured to listen on `0.0.0.0:6667`, exposing the IRC daemon to
any host that can reach the machine. The daemon itself is a legacy/pinned version
with known vulnerabilities (covered in other scenarios). Binding it to all
interfaces unnecessarily increases the attack surface: any host can connect and
probe the daemon, attempt authentication bypasses, or exploit other CVEs.

The compensating control replaces direct external access with a TLS tunnel:

1. `unrealircd.conf` is edited to change the `listen` block from `*:6667` to
   `127.0.0.1:6667`.
2. `stunnel4` is installed and configured to accept TLS connections on
   `0.0.0.0:6697` and proxy them to `127.0.0.1:6667`.
3. Trusted clients connect to port 6697 over TLS; the daemon only sees loopback
   connections.

## Affected Service
- **Service:** UnrealIRCd (Unreal3.2)
- **Port (vulnerable):** 6667/TCP on 0.0.0.0
- **Port (post-remediation):** 6697/TCP (stunnel TLS) on 0.0.0.0 only
- **Config:** /opt/unrealircd/Unreal3.2/unrealircd.conf
- **stunnel config:** /etc/stunnel/stunnel.conf

## Vulnerable Configuration
```
# unrealircd.conf (vulnerable)
listen {
    ip       *;
    port     6667;
    options { };
};
```

## Remediation Steps (Compensating -- no upgrade/removal)
1. Edit `/opt/unrealircd/Unreal3.2/unrealircd.conf`:
   Change `ip *;` to `ip 127.0.0.1;` in the listen block.

2. Install stunnel4 (already present in container):
   ```
   apt-get install -y stunnel4
   ```

3. Create `/etc/stunnel/stunnel.conf`:
   ```ini
   pid = /var/run/stunnel4/stunnel4.pid
   cert = /etc/stunnel/stunnel.pem

   [ircs]
   accept  = 0.0.0.0:6697
   connect = 127.0.0.1:6667
   ```
   A self-signed cert at `/etc/stunnel/stunnel.pem` is pre-generated in the image.

4. Restart UnrealIRCd and start stunnel:
   ```
   su -s /bin/bash boba_fett -c "cd /opt/unrealircd/Unreal3.2 && ./unreal restart"
   stunnel /etc/stunnel/stunnel.conf
   ```

## Build
```
docker build -f scenario-15/Dockerfile -t meta3u-s15 .
docker run -d --name meta3u-s15 -p 6697:6697 meta3u-s15
docker exec meta3u-s15 /bin/bash /verify.sh
docker stop meta3u-s15 && docker rm meta3u-s15
```
