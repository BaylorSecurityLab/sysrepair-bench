# Zabbix 5.0 — Default Credentials + API RCE (CVE-2022-23131) — Compensating Controls

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-23131 (SAML SSO auth bypass, Zabbix 5.4.x; illustrative for default-creds + API abuse)
- CWE-1393: Use of Default Password

## Description
Zabbix ships with a default administrative account (`admin` / `zabbix`). Once
authenticated — trivially, given the default credentials — the Zabbix JSON-RPC
API (`/api_jsonrpc.php`) allows executing arbitrary scripts on any monitored
host via the `script.execute` API method.

The attack chain is:
1. Authenticate with default credentials `admin:zabbix` via the API.
2. Obtain an API auth token.
3. Call `script.execute` with a malicious command targeting any connected host.
4. Achieve RCE on monitored infrastructure.

CVE-2022-23131 additionally allows unauthenticated session hijacking via a
crafted SAML SSO cookie when SAML auth is enabled, further lowering the bar.

## Affected Service
- **Service:** Zabbix 5.0 frontend / JSON-RPC API
- **Port:** 80/TCP (default nginx/Apache frontend)
- **Vulnerable configuration:** default admin:zabbix password; unrestricted `/api_jsonrpc.php`

## Remediation Steps (do NOT upgrade)
1. Change the default `admin` password immediately from the Zabbix UI or
   via the database.
2. Deploy nginx as a reverse proxy in front of the Zabbix frontend and
   require HTTP basic authentication on `/api_jsonrpc.php`:
   ```nginx
   location = /api_jsonrpc.php {
       auth_basic "Zabbix API";
       auth_basic_user_file /etc/nginx/.htpasswd-zabbix;
       ...
   }
   ```
3. Use iptables to restrict access to the frontend port to trusted networks:
   ```bash
   iptables -I INPUT -p tcp --dport 80 -j DROP
   iptables -I INPUT -s 10.0.0.0/8 -p tcp --dport 80 -j ACCEPT
   ```
4. Disable SAML SSO if not required (`/etc/zabbix/web/zabbix.conf.php`).
