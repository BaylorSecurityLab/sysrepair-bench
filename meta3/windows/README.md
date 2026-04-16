# SysRepair-Bench: Metasploitable 3 (Windows) Sub-Suite

## Status

**Phase 1 + 2 scaffolding has landed** — see [docs/PLAN.md](../../docs/PLAN.md) for the full container build plan and [run-sequential.ps1](run-sequential.ps1) for the harness. The authoring pipeline is proven end-to-end on four low-friction scenarios:

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


This README documents:
1. The **proposed scope** sourced from the Rapid7 [metasploitable3 Packer/Vagrant build scripts](https://github.com/rapid7/metasploitable3) — this is the ground truth for what vulnerabilities Meta3-Windows ships with, and scan findings will largely overlap it.
2. The **container strategy** for each candidate scenario (Server Core base, silent installers, port mappings, isolation mode).
3. The **host prerequisites** the benchmark runner needs.

## Container strategy

### Base image

**`mcr.microsoft.com/windows/servercore:ltsc2019`** (or `ltsc2022`) — not Nano Server. The legacy installers used by Meta3-Windows (ManageEngine Desktop Central 9, GlassFish 4, ColdFusion, older JDK/JRE, 32-bit WoW64 binaries) depend on the Server Core API surface. Nano Server strips 32-bit support and several COM/WMI components that these installers rely on.

Rapid7's build targets Windows Server 2008 R2, which is not available as a container base (Microsoft only supports Server 2016+ container images). Server Core LTSC gives us the full legacy API surface; the specific vulnerable app versions are preserved by pinning the installers rather than the kernel.

### Isolation mode

- **Process isolation** works when the container's Windows build matches the host's build (e.g. Windows 11 22H2 host ↔ Server Core ltsc2022 container is usually fine with `--isolation=process`).
- **Hyper-V isolation** (`--isolation=hyperv`) is the safe default — it pins the kernel per container and keeps a mismatched host kernel from breaking older installers. Slower startup, heavier memory.
- Scenarios that rely on specific kernel behavior (EternalBlue-era SMB surface, NTLM relay) will document which isolation mode they require.

### Dockerfile pattern

```dockerfile
FROM mcr.microsoft.com/windows/servercore:ltsc2019
SHELL ["powershell", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop';"]

# Example: install a pinned vulnerable version silently
RUN Invoke-WebRequest -Uri '<pinned-installer-url>' -OutFile 'C:\\install.exe'; \
    Start-Process -FilePath 'C:\\install.exe' -ArgumentList '/S','/quiet' -Wait; \
    Remove-Item 'C:\\install.exe'

EXPOSE <vuln-service-port>
CMD ["powershell", "-NoProfile", "-Command", "Start-Service <svc>; while ($true) { Start-Sleep 60 }"]
```

Every installer must run silently (`/S`, `/quiet`, `/qn`, or MSI `/passive /norestart`) — Windows containers have no desktop, so any GUI prompt hangs the build.

### Agent connectivity

Same sequential-port-mapping pattern as the Ubuntu sub-suite. The agent runs on the host and reaches each container via `localhost:<mapped-port>`:

| Target service | Typical host port |
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

Port-forward (`-p localhost:<host>:<container>`) keeps the benchmark portable; transparent-network setups are avoided because they require Hyper-V external switches and DHCP reservations that aren't reproducible across laptops, cloud VMs, and CI runners.

## Proposed scenario index (subject to scan)

Sourced from the Rapid7 `metasploitable3-windows` Vagrant/Packer tree. Final numbering and compensating-control split will be set once the OpenVAS scan is ingested and overlaps are pruned.

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

## Host prerequisites

- Windows 10/11 Pro/Enterprise or Windows Server 2019+ (Home editions don't support Hyper-V isolation or the Windows Containers feature set)
- Docker Desktop in **Windows Containers** mode, or a native Windows `dockerd` install
- Hyper-V and Containers Windows features enabled (`Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`; `Enable-WindowsOptionalFeature -Online -FeatureName Containers -All`)
- ~40 GB free disk for the Server Core base image plus per-scenario layers
- Internet access for pinned installer downloads at build time (or an offline mirror if building air-gapped)

## Next steps

1. Upload the Windows OpenVAS scan PDF to `../../openvas-scan-reports/metasploitable-3.0-win-openvas.pdf`.
2. Diff the scan's NVT list against the candidate scenarios above; prune anything that isn't scan-observable and promote any scan findings that aren't on the candidate list.
3. Author `scenario-NN/` folders (`Dockerfile` + `threat.md` + `verify.sh`) one section at a time — config-hardening first (fastest feedback on the Server Core base), then patch-management, then compensating-controls last.
