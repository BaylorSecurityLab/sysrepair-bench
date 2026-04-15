# SysRepair-Bench: Metasploitable 3 (Ubuntu) Sub-Suite

## Overview

Docker scenarios derived from the **Metasploitable 3 (Ubuntu 14.04)** target. Scope selection is driven by the OpenVAS scan in [`../../openvas-scan-reports/metasploitable-3.0-ubu-openvas.pdf`](../../openvas-scan-reports/metasploitable-3.0-ubu-openvas.pdf) (Apr 2026, 523 filtered results across the host `10.104.2.154`) combined with the documented Meta3-Ubuntu design surface (Drupal `payroll_app.php`, credential reuse, Docker group escalation, WEBrick admin endpoints).

Every scenario is remediable with **system administration actions** (config edits, package upgrades, service management, permission fixes, firewall rules, WAF / mod_rewrite guards). Scenarios in the **Compensating Controls** band intentionally keep the vulnerable service running — the agent cannot simply upgrade or uninstall; it must apply a network- or config-layer mitigation while preserving service reachability.

## No-overlap policy

Each scenario in this sub-suite targets a vulnerability that is **not already covered** by `meta2/`, `ccdc/`, or `vulnhub/`. The list below was pruned against those suites' indices — anything already present there (e.g. SSH weak ciphers, MySQL empty password, Apache TRACE, both UnrealIRCd CVEs, Ubuntu EOL default-deny, MySQL bind-0.0.0.0, generic outdated OpenSSL) was dropped from the meta3 scope rather than re-implemented on a new base image.

See [Excluded to avoid overlap](#excluded-to-avoid-overlap) at the bottom for the explicit drop list.

## Scope

**In scope (sys-admin layer, meta3-unique):**
- Config hardening surfaces that appear in the scan but are not covered by meta2/ccdc (SSH KEX and host-key algorithms, CUPS TLS posture, unprotected installer pages)
- Service-specific CVEs unique to the Meta3-Ubuntu software stack (Drupal Drupalgeddon, ProFTPD mod_copy, recent Samba USN)
- Meta3-design-surface remediation: payroll-DB credential reuse, Docker group = root, WEBrick admin exposure
- Compensating controls for the Meta3-specific legacy stack (Drupal, ProFTPD, UnrealIRCd, MySQL, payroll app) where upgrade/removal would break the documented attack chain but the agent must keep the service reachable

**Out of scope:**
- Anything already implemented in `meta2/`, `ccdc/`, or `vulnhub/` — see drop list
- Source-code fixes (payroll_app.php SQLi logic, Drupal module XSS) — here we lock down the exposed surface with configuration/WAF
- Windows-only vulnerabilities — see [`../windows/`](../windows/README.md)
- Zero-days with no published remediation

## Base image

All Ubuntu scenarios use `ubuntu:14.04` as the base, with repo URLs pinned to `old-releases.ubuntu.com` (14.04 is EOL). No special kernel flags are required — `ubuntu:14.04` boots cleanly on modern Docker hosts (unlike the `meta2/` Hardy base, which needs `vsyscall=emulate`).

## Proposed scenario index (pending Dockerfile/threat/verify authoring)

### Configuration hardening — S01–S05

| ID | Vulnerability | Port | Scan source |
|---|---|---|---|
| S01 | SSH Weak Key Exchange (KEX) Algorithms | 22 | "Weak Key Exchange (KEX) Algorithm(s) Supported (SSH)" |
| S02 | SSH Weak Host Key Algorithms | 22 | "Weak Host Key Algorithm(s) (SSH)" |
| S03 | CUPS deprecated TLSv1.0 / TLSv1.1 | 631 | "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection" |
| S04 | CUPS / HTTPS weak cipher suites | 631 | "SSL/TLS: Report Vulnerable Cipher Suites for HTTPS" |
| S05 | Unprotected installer pages (Drupal `install.php`, phpMyAdmin setup) | 80 | "Unprotected Web App / Device Installers (HTTP)" |
| S18 | Drupal `web.config` sensitive file disclosure (IIS artifact served by Apache) | 80 | "Sensitive File Disclosure (HTTP)" — `/drupal/web.config` |
| S19 | phpMyAdmin admin interface exposed over cleartext HTTP, no source restriction | 80 | "Cleartext Transmission of Sensitive Information via HTTP" — `/phpmyadmin/:pma_password` |

### Dependency / patch management — S06–S09

| ID | Vulnerability | Port | CVE |
|---|---|---|---|
| S06 | Drupal 7.x Drupalgeddon SQL injection → RCE | 80 | CVE-2014-3704 |
| S07 | ProFTPD 1.3.5 `mod_copy` arbitrary file copy | 21 | CVE-2015-3306 |
| S08 | Samba (USN-7826-2) — WINS hook RCE / `streams_xattr` infoleak | 445 | CVE-2025-10230, CVE-2025-9640 |
| S09 | jQuery < 1.9.0 XSS in Drupal-shipped assets | 80 | scan-detected |

### Access control — S10–S11

| ID | Vulnerability | Surface |
|---|---|---|
| S10 | Credential reuse — payroll DB rows == OS user passwords | `/var/www/html/payroll_app.php` → Linux shadow |
| S11 | `docker` group membership == root (privilege escalation) | host |

### Network exposure — S12

| ID | Vulnerability | Port |
|---|---|---|
| S12 | WEBrick admin HTTP endpoint bound to `0.0.0.0` | 3500 |

### Compensating controls — S13–S17

Agent must keep the service reachable on its documented port; direct upgrade or removal is forbidden by scenario constraints (legacy dependency / pinned version / app-source lock).

| ID | Vulnerability | Compensating control |
|---|---|---|
| S13 | Drupal 7.31 pinned (legacy module incompatible with 7.32+) | mod_security rule / `mod_rewrite` guard blocking the Drupalgeddon `q[%23post_render][]` payload shape |
| S14 | ProFTPD 1.3.5 pinned (legacy client using `SITE` extensions) | Disable only `mod_copy` in `/etc/proftpd/modules.conf`; keep FTP reachable on 21 |
| S15 | UnrealIRCd version pinned (legacy bots) | Bind listener to `127.0.0.1`, front with `stunnel` for trusted clients — addresses exposure surface without touching the (meta2-covered) backdoor/spoofing CVEs |
| S16 | MySQL 5.5 must stay remotely reachable for one trusted app | `bind-address = <trusted-iface>` + `/etc/hosts.allow` source-IP allowlist, keeping 3306 up for the whitelisted peer only |
| S17 | `payroll_app.php` source-locked (SQLi can't be patched in code) | Apache `mod_security` rule blocking tautology / UNION payloads on `/payroll_app.php` POST bodies, keeping the app usable for legitimate logins |

**Total: 19 scenarios, all meta3-unique.** (S18 and S19 are config-hardening scenarios added after a second scan audit; they're numbered after the compensating-control block to preserve the existing S01–S17 IDs.)

### Config hardening, added post-audit — S18–S19

| ID | Vulnerability | Port | Remediation |
|---|---|---|---|
| S18 | `/drupal/web.config` served by Apache (IIS config artifact leaks application layout) | 80 | Apache vhost `<Files web.config> Require all denied` (or `<FilesMatch "\.config$">`) — scoped so Drupal itself stays reachable |
| S19 | `/phpmyadmin/` login form posts `pma_password` over cleartext HTTP and accepts connections from any source | 80 | Apache `<Location /phpmyadmin> Require ip 127.0.0.1</Location>` + HTTP→HTTPS redirect (or `Require local`); phpMyAdmin stays usable for the trusted source |

## Build strategy — vendored Chef recipes

Meta3-Ubuntu's software stack (Drupal 7.31, ProFTPD 1.3.5, payroll_app, phpMyAdmin 3.5.8, UnrealIRCd, Samba, etc.) is already expressed as a Chef cookbook in [rapid7/metasploitable3](https://github.com/rapid7/metasploitable3) (BSD-3-Clause). Rather than re-author the install logic, scenarios vendor the relevant recipes into [`shared/cookbooks/metasploitable/`](shared/) and invoke `chef-solo` at build time.

Two upstream-to-container patches are applied once in the vendored copy:

1. `attributes/default.rb` — `files_path` changed from `/vagrant/chef/cookbooks/metasploitable/files/` to `/cookbooks/metasploitable/files/` so recipes resolve under the container's `COPY`ed path.
2. Upstart-bound recipes (`proftpd`, `sinatra`, `unrealircd`, `readme_app`, `chatbot`, `flags`) have the `service` resource blocks stripped — Docker has no init; daemons are started via the scenario's `CMD` or a foreground entrypoint instead.

The Drupal, `payroll_app`, Samba, and phpMyAdmin recipes require neither patch.

Upstream BSD-3-Clause attribution lives in [`shared/UPSTREAM_LICENSE`](shared/UPSTREAM_LICENSE). Only the recipes and resource files we actually build against are vendored; the Vagrantfile, packer templates, Windows `.bat` scripts, and unrelated cookbooks are not copied.

### Per-scenario Dockerfile skeleton

```dockerfile
FROM ubuntu:14.04

# repo pins for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g; s|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y curl ca-certificates

# Chef 13.8.5 via Omnibus (not in apt for 14.04)
RUN curl -L https://omnitruck.chef.io/install.sh | bash -s -- -v 13.8.5

COPY shared/cookbooks /cookbooks
COPY solo.rb scenario.json /
RUN chef-solo -c /solo.rb -j /scenario.json

COPY verify.sh /verify.sh
EXPOSE <scenario-port>
CMD ["/entrypoint.sh"]
```

`scenario.json` carries a minimal run-list (e.g. `{"run_list": ["recipe[metasploitable::drupal]"]}`) plus any per-scenario attribute overrides. `entrypoint.sh` starts the daemons the stripped-out `service` blocks would have started (e.g. `apache2ctl -D FOREGROUND`, `proftpd --nodaemon`).

### Run loop

```bash
cd scenario-01
docker build -t meta3u-s01 .
docker run -d --name meta3u-s01 -p 2222:22 meta3u-s01

# agent connects via localhost:2222 and performs remediation

docker exec meta3u-s01 /bin/bash /verify.sh
# exit 0 = remediated + service still operational; exit 1 = still vulnerable or regressed

docker stop meta3u-s01 && docker rm meta3u-s01
```

Host port assignments (tentative — finalized per scenario Dockerfile):

| Scenario port | Host port |
|---|---|
| 22 (SSH) | 2222 |
| 21 (FTP) | 2121 |
| 80 (HTTP) | 8080 |
| 445 (SMB) | 4445 |
| 631 (CUPS) | 6631 |
| 3306 (MySQL) | 3306 |
| 3500 (WEBrick) | 3500 |
| 6697 (IRC) | 6697 |

## Excluded to avoid overlap

The following OpenVAS findings / known Meta3-Ubuntu vulns were **dropped** because an equivalent scenario already exists in a sibling suite:

| Dropped | Already covered by |
|---|---|
| SSH weak ciphers | `meta2/` S01 |
| SSH weak MAC algorithms | `meta2/` S02 |
| SSH default credentials | `meta2/` S03 |
| FTP default / anonymous credentials | `meta2/` S04, S05 |
| MySQL root empty password | `meta2/` S06 |
| Apache TRACE / dangerous methods | `meta2/` S10, `ccdc/` S08 |
| Apache PUT/DELETE (WebDAV) | `meta2/` S11 |
| HTTP cleartext credential forms | `meta2/` S25 |
| UnrealIRCd backdoor (CVE-2010-2075) | `meta2/` S17 |
| UnrealIRCd auth spoofing (CVE-2016-7144) | `meta2/` S18 |
| MySQL bound to `0.0.0.0` | `ccdc/` S11 |
| Samba anonymous share access | `ccdc/` S18 |
| Ubuntu EOL default-deny host firewall | `meta2/` S39 (same compensating-control pattern) |
| Generic outdated OpenSSL / Python / glibc USNs | `ccdc/` S33 (outdated OpenSSL CVE); generic patch-mgmt is not re-implemented per-suite |

The compensating-control variants in S13–S17 are kept because they target the Meta3-specific software stack (Drupal 7.31, ProFTPD 1.3.5, Meta3's UnrealIRCd build, MySQL 5.5, payroll_app.php) which no sibling suite covers.
