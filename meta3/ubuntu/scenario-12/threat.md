# WEBrick Admin HTTP Endpoint Bound to 0.0.0.0:3500

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-668: Exposure of Resource to Wrong Sphere
- No individual CVE -- configuration weakness

## Description
The Metasploitable 3 Ubuntu target runs a Ruby WEBrick HTTP server exposing an
admin control panel at `/admin` on port 3500. The server is configured with
`:BindAddress => '0.0.0.0'`, which causes it to listen on all network interfaces,
including the externally-reachable one.

Any host on the network that can reach port 3500 can access the admin panel
without authentication. Depending on what administrative actions the panel
exposes (service restarts, file operations, user management), this may allow
full system compromise from an unprivileged network position.

In the Metasploitable 3 design this endpoint is part of the attack chain:
an external attacker reaches the panel over the Docker-bridged network and
uses it as a foothold for lateral movement.

## Affected Service
- **Service:** WEBrick HTTP server (Ruby)
- **Port:** 3500/TCP
- **Script:** /opt/admin_app.rb
- **Bind address (vulnerable):** 0.0.0.0

## Vulnerable Configuration
```ruby
# /opt/admin_app.rb (vulnerable)
server = WEBrick::HTTPServer.new(
  :BindAddress => '0.0.0.0',
  :Port        => 3500
)
```

## Remediation Steps
Choose one of the following approaches:

**Option A -- Restrict bind address (preferred):**
Edit `/opt/admin_app.rb` and change `:BindAddress` from `'0.0.0.0'` to
`'127.0.0.1'`, then restart the process:
```
kill $(pgrep -f admin_app.rb)
ruby /opt/admin_app.rb &
```

**Option B -- iptables rule:**
Block inbound connections to port 3500 from non-loopback sources:
```
iptables -I INPUT -p tcp --dport 3500 ! -i lo -j DROP
```

**Option C -- ufw:**
```
ufw deny in on eth0 to any port 3500
```

## Verification
After remediation:
- `curl http://localhost:3500/admin` from inside the container must still return 200.
- `ss -tlnp | grep 3500` must show `127.0.0.1:3500`, not `0.0.0.0:3500` (for option A).

## Build
```
docker build -f scenario-12/Dockerfile -t meta3u-s12 .
docker run -d --name meta3u-s12 -p 3500:3500 meta3u-s12
docker exec meta3u-s12 /bin/bash /verify.sh
docker stop meta3u-s12 && docker rm meta3u-s12
```
