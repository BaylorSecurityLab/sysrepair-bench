# SysRepair-Bench: Metasploitable 3 (Windows) Sub-Suite

## Status

**21/21 scenarios authored** — each `scenario-NN-*/` folder carries a Dockerfile (or Packer/Hyper-V provider where process-isolation is insufficient), threat.md, a behavioral verify probe, and a harness-compatible manifest. The sequential harness lives in [run-sequential.ps1](run-sequential.ps1). Scan source: [`../../openvas-scan-reports/metasploitable-3.0-win-openvas.pdf`](../../openvas-scan-reports/metasploitable-3.0-win-openvas.pdf).

| # | Folder | Vuln | Upstream source |
|---|---|---|---|
| 01 | [scenario-01-snmp/](scenario-01-snmp/) | SNMP `public` RW community, no manager allow-list | `scripts/installs/setup_snmp.bat` |
| 02 | [scenario-02-iis/](scenario-02-iis/) | IIS directory browsing + HTTP TRACE allowed | `scripts/installs/setup_iis.bat` |
| 03 | [scenario-03-ftp/](scenario-03-ftp/) | IIS FTP anonymous read+write | `scripts/installs/setup_ftp_site.bat` |
| 04 | [scenario-04-tomcat/](scenario-04-tomcat/) | Tomcat 8.0.33 default `tomcat/tomcat` Manager creds, RemoteAddrValve removed | `scripts/chocolatey_installs/tomcat.bat` |
| 05 | [scenario-05-struts/](scenario-05-struts/) | Struts 2.3.15.1 REST Showcase — Jakarta Multipart OGNL RCE (CVE-2017-5638 / S2-045) | `scripts/installs/setup_apache_struts.bat` |
| 06 | [scenario-06-jenkins/](scenario-06-jenkins/) | Jenkins 2.32.1 — pre-auth CLI remoting deserialization (CVE-2017-1000353), `useSecurity=false` | `scripts/installs/setup_jenkins.bat` |
| 07 | [scenario-07-glassfish/](scenario-07-glassfish/) | GlassFish 4.0 — admin traversal (CVE-2017-1000028) + empty `admin` password + 4848 on 0.0.0.0 | `scripts/installs/setup_glassfish.bat` |
| 08 | [scenario-08-axis2/](scenario-08-axis2/) | Axis2 1.6.0 — default `admin/axis2` creds → AAR upload RCE | `scripts/installs/setup_axis2.bat` |
| 09 | [scenario-09-elasticsearch/](scenario-09-elasticsearch/) | Elasticsearch 1.1.1 — dynamic-scripting RCE (CVE-2014-3120) | `scripts/installs/install_elasticsearch.bat` |
| 10 | [scenario-10-smbv1/](scenario-10-smbv1/) | SMBv1 dialect enabled (EternalBlue precondition, CVE-2017-0144 class) | OS baseline — `Set-SmbServerConfiguration -EnableSMB1Protocol $true` |
| 11 | [scenario-11-smb-signing/](scenario-11-smb-signing/) | SMB signing not required (NTLM relay surface) | OS baseline — `RequireSecuritySignature=False` |
| 12 | [scenario-12-rdp-nla/](scenario-12-rdp-nla/) | RDP with NLA disabled (pre-auth attack surface; BlueKeep-class exposure) | OS baseline — `UserAuthentication=0` |
| 13 | [scenario-13-llmnr-nbtns/](scenario-13-llmnr-nbtns/) | LLMNR + NBT-NS enabled (Responder / ntlmrelayx bait) | OS baseline — `EnableMulticast=1`, `NetbiosOptions=1` |
| 14 | [scenario-14-unquoted-service-path/](scenario-14-unquoted-service-path/) | Unquoted service ImagePath + user-writable parent dir (SYSTEM priv-esc) | OS baseline — CWE-428 |
| 15 | [scenario-15-wamp-wordpress/](scenario-15-wamp-wordpress/) | WordPress 4.7.1 — weak `admin:admin` + CVE-2017-1001000 REST API | `scripts/installs/install_wamp.bat` + `install_wordpress.bat` |
| 16 | [scenario-16-manageengine/](scenario-16-manageengine/) | ManageEngine Desktop Central 9 — FileUploadServlet upload RCE (CVE-2015-8249) | `scripts/installs/install_manageengine_desktopcentral.bat` |
| 17 | [scenario-17-stickykeys-backdoor/](scenario-17-stickykeys-backdoor/) | `sethc.exe` replaced with `cmd.exe` — logon-screen SYSTEM shell (T1546.008) | Operator-planted |
| 18 | [scenario-18-scheduled-task-backdoor/](scenario-18-scheduled-task-backdoor/) | Hidden SYSTEM scheduled task running payload from `C:\Users\Public` (T1053.005) | Operator-planted |
| 19 | [scenario-19-rogue-listener-service/](scenario-19-rogue-listener-service/) | `WinTelemetrySvc` PowerShell bind shell on 4444/TCP (T1543.003) | Operator-planted |
| 20 | [scenario-20-hidden-admin-account/](scenario-20-hidden-admin-account/) | Local admin `support$` with RID-hiding suffix (T1136.001) | Operator-planted |
| 21 | [scenario-21-ssh-defaults/](scenario-21-ssh-defaults/) | OpenSSH-Win32 7.1.0.0-beta + `vagrant:vagrant` admin (CVE-2016-1908/6210/6515, CVE-2017-15906, CVE-2018-15473) | Rapid7 Vagrant provisioning channel |


## Suite-specific notes

**Base image:** `mcr.microsoft.com/windows/servercore:ltsc2019` (or `ltsc2022`) — not Nano Server. The legacy Meta3-Windows installers (ManageEngine Desktop Central 9, GlassFish 4, ColdFusion, older JDK/JRE, 32-bit WoW64 binaries) depend on the Server Core API surface; Nano Server strips 32-bit support and several COM/WMI components they rely on. Rapid7's upstream build targets Server 2008 R2 (no container base exists below Server 2016), so Server Core LTSC is used and the specific vulnerable app versions are pinned at install time.

**Isolation:** the harness auto-injects `--isolation=hyperv` for every Windows-container scenario (see root README §3c). Scenarios that rely on specific kernel behavior (EternalBlue-era SMB surface, NTLM relay) require Hyper-V isolation; a few scenarios ship a Hyper-V Packer provider where container process/kernel coupling is insufficient (e.g. S13 LLMNR/NBT-NS).

**Silent installers:** every installer must run silently (`/S`, `/quiet`, `/qn`, or MSI `/passive /norestart`) — Windows containers have no desktop, so any GUI prompt hangs the build.

### Per-service host-port mapping

| Target service | Host port |
|---|---|
| WinRM (5985/HTTP, 5986/HTTPS) | 5985 / 5986 |
| SSH (if OpenSSH installed) | 2222 |
| SMB (445) | 4445 |
| IIS (80 / 443) | 8080 / 8443 |
| Jenkins (8080) | 9090 |
| GlassFish admin (4848) | 4848 |
| Tomcat (8282) | 8282 |
| ManageEngine Desktop Central (8040) | 8040 |
| ElasticSearch (9200) | 9200 |

## Candidate vulnerability surface (reference)

The tables below enumerate the Rapid7 `metasploitable3-windows` Vagrant/Packer vulnerability surface. They are kept here as a **scope reference** — the authoritative list of what is actually built is the `scenario-NN-*/` folder table at the top of this file.

### Configuration hardening

| Candidate | Vulnerability | Port |
|---|---|---|
| WinRM unencrypted HTTP listener enabled | WinRM clear-text admin channel | 5985 |
| SMB signing not required (SMBv1 fallback) | NTLM relay surface | 445 |
| IIS directory browsing enabled | Information disclosure | 80 |
| IIS TRACE / WebDAV methods enabled | Legacy method abuse | 80 |
| RDP NLA disabled | Pre-auth attack surface on RDP | 3389 |
| Windows firewall disabled / all-allow | Default-deny missing | host |
| SNMP `public` community string | Credential / info disclosure | 161/udp |
| Unquoted service paths in PATH | Priv-esc staging | host |
| LSA protection / LLMNR / NBT-NS left enabled | Credential theft surface | host |

### Dependency / patch management

| Candidate | Vulnerability | Port / Service |
|---|---|---|
| Apache Struts 2 — OGNL RCE | CVE-2017-5638 (S2-045) | 8080 (Struts app) |
| Jenkins old CLI deserialization | CVE-2017-1000353 / CVE-2015-8103 | 9090 |
| ManageEngine Desktop Central 9 | FileUploadServlet arbitrary upload | 8020 / 8040 |
| GlassFish 4.0 default admin creds + traversal | CVE-2017-1000028 + default creds | 4848 / 8080 |
| ElasticSearch 1.1.1 Groovy scripting RCE | CVE-2014-3120 | 9200 |
| ColdFusion dir traversal | CVE-2010-2861 | 8500 |
| Apache Tomcat default `manager` creds | deploy-WAR to RCE | 8282 |
| WebDAV IIS ScStoragePathFromUrl | CVE-2017-7269 | 80 |
| SMB EternalBlue preconditions (SMBv1 on) | CVE-2017-0144 (documented, not exploited in-container) | 445 |

### Access control

| Candidate | Vulnerability |
|---|---|
| `vagrant / vagrant` default local admin |
| RDP default creds |
| Tomcat manager `tomcat / tomcat` |
| Jenkins admin `admin / admin` |
| ManageEngine default admin |
| Guest account enabled with share access |

### Network exposure

| Candidate | Vulnerability |
|---|---|
| Tomcat manager reachable on `0.0.0.0` |
| Jenkins master reachable without auth token |
| ElasticSearch bound to all interfaces |
| GlassFish admin 4848 exposed externally |

### Compensating controls (service must stay usable)

| Candidate | Compensating control |
|---|---|
| Struts app pinned to 2.3.x | WAF rule filtering `Content-Type` OGNL payloads |
| Legacy ColdFusion can't be upgraded | IIS URL rewrite blocking traversal patterns |
| Tomcat manager must be reachable for one deploy host | `RemoteAddrValve` allowlist instead of removal |
| ElasticSearch 1.1.1 pinned for legacy analytics | Windows Firewall rule scoping 9200 to trusted subnet |
| ManageEngine 9 can't be replaced | Reverse-proxy auth in front of `/fileupload` endpoint |

## Next steps

1. Run the sequential harness end-to-end on a Windows host and record per-scenario timing / isolation-mode notes.
2. Promote any Windows scan findings not yet represented in S01–S21 into a new scenario.
3. Add compensating-control variants for the scenarios where the vulnerable version is legacy-pinned (Struts 2.3.x WAF rule, ManageEngine 9 reverse-proxy, ElasticSearch 1.1.1 firewall scope) once the core S01–S21 harness run is green.
