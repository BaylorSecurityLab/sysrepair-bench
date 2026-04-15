# phpMyAdmin Admin Interface Exposed: Cleartext HTTP, No Source Restriction

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-284: Improper Access Control
- OpenVAS: "Cleartext Transmission of Sensitive Information via HTTP" — `/phpmyadmin/:pma_password`

## Description
The phpMyAdmin login interface at `/phpmyadmin/` is served over cleartext HTTP
and accepts connections from any remote IP address. Two distinct weaknesses are
present:

1. **Cleartext transmission:** The login form POSTs `pma_password` (the MySQL
   password) over plain HTTP. Any network observer positioned between the client
   and the server — on a shared LAN, through a rogue access point, or via ARP
   spoofing — can capture the credential in cleartext from a single packet
   capture.

2. **No source restriction:** The Apache configuration places no `Require ip`
   or `Order`/`Allow` directive on `/phpmyadmin/`. The administration interface
   is therefore reachable from any routable IP, exposing MySQL management
   capabilities (arbitrary SQL, file read/write via `LOAD DATA INFILE`,
   `INTO OUTFILE`) to the entire network.

Together these weaknesses mean a remote attacker can both intercept credentials
and use them directly to gain unrestricted MySQL access.

## Affected Service
- **Service:** Apache2 + phpMyAdmin 3.5.8
- **Port:** 80/TCP
- **Path:** `/phpmyadmin/`

## Vulnerable Configuration
```
# /etc/apache2/conf.d/phpmyadmin.conf (or equivalent)
# No Require / Allow directive present — all sources accepted
Alias /phpmyadmin /var/www/phpmyadmin
```

## Remediation Steps
1. Restrict `/phpmyadmin/` to localhost only by adding an Apache `<Location>`
   block. Place this in `/etc/apache2/conf.d/phpmyadmin.conf` or the active
   virtual host file.

   **Apache 2.4 syntax:**
   ```apache
   <Location /phpmyadmin>
       Require ip 127.0.0.1
       Require ip ::1
   </Location>
   ```

   **Apache 2.2 syntax:**
   ```apache
   <Location /phpmyadmin>
       Order deny,allow
       Deny from all
       Allow from 127.0.0.1
       Allow from ::1
   </Location>
   ```

2. Reload Apache:
   ```bash
   service apache2 reload
   ```

3. To address the cleartext transmission issue, also configure an HTTPS
   virtual host with a self-signed certificate and redirect `/phpmyadmin`
   from HTTP to HTTPS. In test environments where HTTPS cannot be easily
   verified, the source-restriction control alone is accepted as the primary
   compensating measure.

4. Verify that the Apache configuration contains the allowlist directive:
   ```bash
   grep -r 'Require ip\|Allow from 127' /etc/apache2/
   ```
   And that requests from non-localhost addresses receive 403.

## Build

Build from the `meta3/ubuntu/` directory (one level above this scenario):

```
docker build -f scenario-19/Dockerfile -t meta3u-s19 .
docker run -d --name meta3u-s19 -p 8080:80 meta3u-s19
docker exec meta3u-s19 /bin/bash /verify.sh
docker stop meta3u-s19 && docker rm meta3u-s19
```
