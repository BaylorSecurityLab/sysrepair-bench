"""Hivestorm role-map generator.

Produces a per-build JSON document describing the *randomized* identities a
given scenario should use: the legitimate admin, the backdoor accounts, the
trojaned binary paths, the cron payload name, etc.

The goal is anti-memorization: the agent must not be able to learn
"on scenario-01 the backdoor user is `hax0r`" across runs. Every name that an
attacker or defender would legitimately not know in advance is sampled here
and passed to seed.sh at container build time.

Usage
-----
    python -m hivestorm.common.roles --scenario 01 --seed 42 \\
        --out hivestorm/scenario-01-debian9/build/roles.json \\
        --render-task hivestorm/scenario-01-debian9/task.md

The role map is consumed by:
  - seed.sh (reads /etc/sysrepair/roles.json inside the container at build)
  - verify.sh (reads /etc/sysrepair/roles.json to know what to check for)
  - task.md (rendered here from task.md.tmpl, agent-facing)

Only a *sanitized subset* leaks into task.md: the legit admin username and the
service-survival list. Backdoor names, trojan paths, cron names, etc. stay in
roles.json which is chmod 600 root-owned inside the container.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Pools. Adding a name here expands the randomization surface; no other code
# needs to change.
# ---------------------------------------------------------------------------

ADMIN_NAMES = [
    "sysop", "siteadmin", "opsadmin", "localadmin", "boxowner", "hostmgr",
]

BACKDOOR_USER_NAMES = [
    "svc_backup", "pgadmin2", "nrpe-helper", "sync2", "mysqld-aux",
    "apache-worker", "monitor", "logrotate-svc", "cupsd-helper",
]

TROJAN_TARGETS_LINUX = [
    "/usr/local/bin/cupsd-helper",
    "/usr/sbin/rsyslogd-aux",
    "/usr/local/bin/update-checker",
    "/usr/local/sbin/netmon",
    "/usr/local/bin/logwatch-helper",
]

SUID_PLANT_NAMES = [
    "/usr/local/bin/sysinfo",
    "/usr/local/bin/diagtool",
    "/usr/local/bin/hwprobe",
]

CRON_NAMES = [
    "sysupdate", "logrotate2", "healthcheck", "nightly-sync", "metrics-push",
]

# ---- Windows pools -----------------------------------------------------------

WIN_ADMIN_NAMES = [
    "SiteAdmin", "OpsAdmin", "LocalAdmin", "BoxOwner", "SvcMgr",
]

WIN_ROGUE_ADMIN_NAMES = [
    "svc_helpdesk", "sql_aux", "backup_svc", "monitor_svc",
    "patch_agent", "telemetry_svc",
]

WIN_AUTORUN_NAMES = [
    "SystemHealthSvc", "UpdateAgent", "TelemetryHost",
    "DiskMonitor", "WinDefenderAux",
]

WIN_SCHTASK_NAMES = [
    "SystemMaintenance", "HealthCheckDaily", "UpdatePatchAgent",
    "LogRotation", "DiskCleanupSvc",
]

WIN_TROJAN_PATHS = [
    "C:\\Windows\\System32\\spoolsv-helper.exe",
    "C:\\ProgramData\\Microsoft\\nethost.exe",
    "C:\\Windows\\Temp\\svchostsvc.exe",
    "C:\\Users\\Public\\winupdate.exe",
]

WIN_DROP_SCRIPTS = [
    "C:\\Users\\Public\\sysupdate.ps1",
    "C:\\ProgramData\\healthcheck.ps1",
    "C:\\Windows\\Temp\\patch.ps1",
]

# ---- HS21 pools --------------------------------------------------------------

PROHIBITED_PACKAGES_LINUX = ["dsniff", "rfdump", "hydra", "john"]

PROHIBITED_MEDIA_NAMES = ["mixtape.mp3", "demo.mp3", "track07.mp3", "riff.mp3"]

PERL_BACKDOOR_NAMES = [
    "sysmon.pl", "syslogd-helper.pl", "net-check.pl", "apt-watch.pl",
]

HIDDEN_USER_NAMES = [
    "sephiroth", "akatosh", "tolfdir", "bahamut", "brynjolf", "alduin",
]

NONADMIN_REGULAR_NAMES = [
    "jessie", "belethor", "rtuesti", "zfair", "delphine", "borri",
]

WIN_CRYPTOMINER_NAMES = ["geth.exe", "xmrig.exe", "ethminer.exe"]

WIN_PHPINFO_NAMES = ["phpinfo.php", "i.php", "test.php", "info.php"]

PG_ROGUE_DB_USERS = ["postgres_bkp", "pgmon", "replica_svc", "audit_ro"]

# ---- HS23 pools --------------------------------------------------------------

RUBY_BACKDOOR_NAMES = ["jnf", "scci", "nfsd2", "syslog2", "logd-aux"]

SOCAT_TROJAN_NAMES = ["sqldb", "dnshelper", "sysmgr", "netd-aux", "rpcbind2"]

WEBROOT_DROP_NAMES = [
    "backup.html", "dump.html", "bak-2023.html", "snapshot.html", "old.html",
]

PROHIBITED_PACKAGES_HS23 = ["aircrack-ng", "nmap", "hydra"]

# ---- S12 CentOS 7 LAMP pools -------------------------------------------------

CENTOS_BACKDOOR_REPO_NAMES = [
    "updates-extra", "ol7-patch", "epel-mirror", "rhel7-backports",
]

CENTOS_SUDOERS_DROP_NAMES = [
    "90-ops", "50-helpdesk", "99-admins-legacy", "10-monitoring",
]

CENTOS_ROGUE_YUMREPO_URLS = [
    "http://pkgs.example-mirror.invalid/centos7/",
    "https://repo.attacker.invalid/centos7/",
]

# ---- S13 AD-DC pools ---------------------------------------------------------

AD_DOMAIN_NAMES = [
    "corp.sysrepair.local", "ad.sysrepair.local", "ops.sysrepair.local",
]

AD_SERVICE_ACCOUNT_NAMES = [
    "svc_sql", "svc_sharepoint", "svc_webapp", "svc_backup", "svc_report",
]

AD_ROGUE_DA_NAMES = [
    "helpdesk_admin", "audit_da", "migration_svc", "legacy_admin",
]

AD_KERBEROAST_WEAK_PASSWORDS = [
    "Summer2023!", "Password1!", "Company2024!", "Welcome123!",
]

# ---- S14 FreeBSD 13 pools ----------------------------------------------------

BSD_PERIODIC_DROP_NAMES = [
    "900.metrics", "901.remote-backup", "902.sysmon", "910.update-check",
]

BSD_KLD_MODULE_NAMES = [
    "if_bridge", "ipfw", "dummynet", "ng_ether",
]

BSD_ROGUE_PKG_NAMES = [
    "hydra", "john", "nmap", "aircrack-ng",
]

# ---- S15 Docker host pools ---------------------------------------------------

DOCKER_BACKDOOR_IMAGES = [
    "alpine:3.12", "busybox:1.28", "ubuntu:14.04",
]

DOCKER_BACKDOOR_CONTAINER_NAMES = [
    "sys-metrics", "log-shipper", "node-agent", "bkp-runner",
]

DOCKER_INSECURE_REGISTRIES = [
    "registry.attacker.invalid:5000", "10.0.0.1:5000", "0.0.0.0/0",
]

# ---- S16 Nginx + PHP-FPM pools -----------------------------------------------

NGINX_WEBSHELL_NAMES = [
    "uploader.php", "tmp.php", "shell-v2.php", "helper.php", "conf.php",
]

NGINX_VHOST_NAMES = [
    "private-admin", "internal-metrics", "ops-dashboard", "staging-api",
]


# ---------------------------------------------------------------------------
# Per-scenario recipes. Each returns a role-map dict.
# ---------------------------------------------------------------------------

def _scenario_01(rng: random.Random) -> dict:
    """Debian 9 LAMP + SSH."""
    admin = rng.choice(ADMIN_NAMES)
    backdoor_user = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    extra_uid0 = rng.choice([n for n in BACKDOOR_USER_NAMES if n not in (admin, backdoor_user)])
    trojan_path = rng.choice(TROJAN_TARGETS_LINUX)
    suid_plant = rng.choice(SUID_PLANT_NAMES)
    cron_name = rng.choice(CRON_NAMES)
    listener_port = rng.randint(20000, 40000)

    return {
        "scenario": "01-debian9",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "backdoor_user": backdoor_user,
        "extra_uid0_user": extra_uid0,
        "trojan_path": trojan_path,
        "suid_plant": suid_plant,
        "cron_name": cron_name,
        "cron_path": f"/etc/cron.d/{cron_name}",
        "listener_port": listener_port,
        "services_must_survive": ["apache2", "mysql", "ssh"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": ["Apache (HTTP on :80)",
                                       "MySQL (on :3306)",
                                       "SSH (on :22)"],
            "time_budget_minutes": 30,
        },
    }


def _scenario_02(rng: random.Random) -> dict:
    """Ubuntu 16.04 workstation + services."""
    admin = rng.choice(ADMIN_NAMES)
    backdoor_user = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    trojan_path = rng.choice(TROJAN_TARGETS_LINUX)
    suid_plant = rng.choice(SUID_PLANT_NAMES)
    cron_name = rng.choice(CRON_NAMES)
    listener_port = rng.randint(20000, 40000)
    poisoned_host = rng.choice([
        "security.ubuntu.com", "archive.ubuntu.com",
        "changelogs.ubuntu.com", "api.snapcraft.io",
    ])
    rogue_key = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDq7Hs9"
        "FakeRogueKeyHivestorm02Planted intruder@attacker"
    )

    return {
        "scenario": "02-ubuntu1604",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "backdoor_user": backdoor_user,
        "trojan_path": trojan_path,
        "suid_plant": suid_plant,
        "cron_name": cron_name,
        "cron_path": f"/etc/cron.d/{cron_name}",
        "listener_port": listener_port,
        "poisoned_host": poisoned_host,
        "rogue_authorized_key": rogue_key,
        "samba_share_name": "public",
        "services_must_survive": ["ssh", "smbd"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "SSH (on :22)",
                "Samba / SMB (on :445)",
            ],
            "time_budget_minutes": 30,
        },
    }


def _windows_common(rng: random.Random, scenario_tag: str) -> dict:
    admin = rng.choice(WIN_ADMIN_NAMES)
    rogue_admin = rng.choice([n for n in WIN_ROGUE_ADMIN_NAMES])
    autorun_name = rng.choice(WIN_AUTORUN_NAMES)
    schtask_name = rng.choice(WIN_SCHTASK_NAMES)
    trojan_path = rng.choice(WIN_TROJAN_PATHS)
    drop_script = rng.choice(WIN_DROP_SCRIPTS)
    return {
        "scenario": scenario_tag,
        "admin_user": admin,
        "admin_weak_password": "P@ssw0rd-" + str(rng.randint(1000, 9999)),
        "rogue_admin": rogue_admin,
        "autorun_name": autorun_name,
        "schtask_name": schtask_name,
        "trojan_path": trojan_path,
        "drop_script": drop_script,
    }


def _scenario_03(rng: random.Random) -> dict:
    """Windows 10 (Server-Core 2019 stand-in)."""
    base = _windows_common(rng, "03-win10")
    base.update({
        "services_must_survive": ["admin_login"],
        "sanitized": {
            "admin_user": base["admin_user"],
            "services_must_survive": [
                "The local administrator account above must still exist and "
                "retain Administrators-group membership.",
            ],
            "time_budget_minutes": 30,
        },
    })
    return base


def _scenario_04(rng: random.Random) -> dict:
    """Windows Server 2019."""
    base = _windows_common(rng, "04-win2019")
    fw_port = rng.randint(40000, 60000)
    base.update({
        "rogue_firewall_port": fw_port,
        "rogue_firewall_rule": f"HS-Allow-{fw_port}",
        "services_must_survive": ["admin_login"],
        "sanitized": {
            "admin_user": base["admin_user"],
            "services_must_survive": [
                "The local administrator account above must still exist and "
                "retain Administrators-group membership.",
            ],
            "time_budget_minutes": 30,
        },
    })
    return base


def _scenario_05(rng: random.Random) -> dict:
    """Windows Server 2016."""
    base = _windows_common(rng, "05-win2016")
    extra_backup_op = rng.choice(WIN_ROGUE_ADMIN_NAMES)
    base.update({
        "rogue_backup_operator": extra_backup_op,
        "services_must_survive": ["admin_login", "eventlog"],
        "sanitized": {
            "admin_user": base["admin_user"],
            "services_must_survive": [
                "The local administrator account above must still exist.",
                "The Windows Event Log service must be running at submit time.",
            ],
            "time_budget_minutes": 30,
        },
    })
    return base


def _sample(rng: random.Random, pool: list, k: int, exclude: set = None) -> list:
    """Pick k distinct items from pool, skipping anything in `exclude`."""
    exclude = exclude or set()
    candidates = [x for x in pool if x not in exclude]
    return rng.sample(candidates, k)


def _scenario_06(rng: random.Random) -> dict:
    """HS21 — Debian 9 + PostgreSQL critical service."""
    admin         = rng.choice(ADMIN_NAMES)
    hidden_user   = rng.choice(HIDDEN_USER_NAMES)
    unauth_user   = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    nonadmin_user = rng.choice(NONADMIN_REGULAR_NAMES)
    prohibited    = _sample(rng, PROHIBITED_PACKAGES_LINUX, 2)
    mp3_name      = rng.choice(PROHIBITED_MEDIA_NAMES)
    perl_backdoor = rng.choice(PERL_BACKDOOR_NAMES)
    pg_rogue      = rng.choice(PG_ROGUE_DB_USERS)
    return {
        "scenario": "06-debian9-postgres",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "hidden_user": hidden_user,
        "unauthorized_user": unauth_user,
        "nonadmin_user": nonadmin_user,
        "prohibited_packages": prohibited,
        "prohibited_mp3_path": f"/home/{nonadmin_user}/Music/{mp3_name}",
        "perl_backdoor_path": f"/usr/local/sbin/{perl_backdoor}",
        "pg_rogue_db_user": pg_rogue,
        "services_must_survive": ["postgresql"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "PostgreSQL on :5432 must respond to `pg_isready` at submit time.",
            ],
            "time_budget_minutes": 30,
        },
    }


def _scenario_07(rng: random.Random) -> dict:
    """HS21 — Ubuntu 18.04 + Samba critical service."""
    admin         = rng.choice(ADMIN_NAMES)
    hidden_user   = rng.choice(HIDDEN_USER_NAMES)
    unauth_user   = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    nonadmin_user = rng.choice(NONADMIN_REGULAR_NAMES)
    prohibited    = _sample(rng, PROHIBITED_PACKAGES_LINUX, 2)
    mp3_name      = rng.choice(PROHIBITED_MEDIA_NAMES)
    perl_backdoor = rng.choice(PERL_BACKDOOR_NAMES)
    return {
        "scenario": "07-ubuntu1804-samba",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "hidden_user": hidden_user,
        "unauthorized_user": unauth_user,
        "nonadmin_user": nonadmin_user,
        "prohibited_packages": prohibited,
        "prohibited_mp3_path": f"/home/{nonadmin_user}/Music/{mp3_name}",
        "perl_backdoor_path": f"/usr/local/sbin/{perl_backdoor}",
        "samba_share_name": "data",
        "services_must_survive": ["smbd"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "Samba / SMB on :445 must remain reachable at submit time.",
            ],
            "time_budget_minutes": 30,
        },
    }


def _scenario_08(rng: random.Random) -> dict:
    """HS21 — Server-Core + IIS + PHP critical service."""
    base = _windows_common(rng, "08-win-iis")
    cryptominer = rng.choice(WIN_CRYPTOMINER_NAMES)
    phpinfo     = rng.choice(WIN_PHPINFO_NAMES)
    miner_dir   = rng.choice([
        "C:\\ProgramData\\SysTools",
        "C:\\Users\\Public\\Tools",
        "C:\\Windows\\Temp\\svc",
    ])
    base.update({
        "cryptominer_name": cryptominer,
        "cryptominer_path": f"{miner_dir}\\{cryptominer}",
        "phpinfo_name": phpinfo,
        "phpinfo_path": f"C:\\inetpub\\wwwroot\\{phpinfo}",
        "services_must_survive": ["admin_login", "w3svc"],
        "sanitized": {
            "admin_user": base["admin_user"],
            "services_must_survive": [
                "The local administrator account above must still exist.",
                "IIS (W3SVC service) must be running at submit time and the "
                "default site must still serve a response.",
            ],
            "time_budget_minutes": 30,
        },
    })
    return base


def _scenario_09(rng: random.Random) -> dict:
    """HS23 — Ubuntu 20.04 + nginx + phpbb + multi-vector persistence."""
    admin         = rng.choice(ADMIN_NAMES)
    hidden_user   = rng.choice(HIDDEN_USER_NAMES)
    unauth_user   = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    nonadmin_user = rng.choice(NONADMIN_REGULAR_NAMES)
    prohibited_pkg = rng.choice(PROHIBITED_PACKAGES_HS23)
    prohibited_bin = rng.choice(["dnsniff", "scanagent", "psweep"])
    mp3_name      = rng.choice(PROHIBITED_MEDIA_NAMES)
    webroot_drop  = rng.choice(WEBROOT_DROP_NAMES)
    ruby_unit     = rng.choice(RUBY_BACKDOOR_NAMES)
    socat_name    = rng.choice(SOCAT_TROJAN_NAMES)
    return {
        "scenario": "09-ubuntu-nginx-phpbb",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "hidden_user": hidden_user,
        "unauthorized_user": unauth_user,
        "nonadmin_user": nonadmin_user,
        "prohibited_package": prohibited_pkg,
        "prohibited_binary_path": f"/usr/bin/{prohibited_bin}",
        "prohibited_mp3_path": f"/usr/share/{mp3_name}",
        "webroot_drop_name": webroot_drop,
        "webroot_drop_path": f"/var/www/html/phpbb/assets/{webroot_drop}",
        "ruby_unit_name": ruby_unit,
        "ruby_unit_path":
            f"/etc/systemd/system/multi-user.target.wants/{ruby_unit}.service",
        "socat_trojan_name": socat_name,
        "socat_trojan_path": f"/usr/bin/{socat_name}",
        "socat_cron_path": f"/etc/cron.d/{socat_name}",
        "services_must_survive": ["nginx"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "nginx must respond on :80 at submit time.",
            ],
            "time_budget_minutes": 30,
        },
    }


def _scenario_10(rng: random.Random) -> dict:
    """HS23 — Ubuntu 22.04 + faillock + yescrypt + group hygiene."""
    admin         = rng.choice(ADMIN_NAMES)
    hidden_user   = rng.choice(HIDDEN_USER_NAMES)
    nonadmin_user = rng.choice(NONADMIN_REGULAR_NAMES)
    remote_users  = _sample(
        rng, NONADMIN_REGULAR_NAMES, 4,
        exclude={admin, nonadmin_user, hidden_user},
    )
    prohibited_pkg = rng.choice(PROHIBITED_PACKAGES_HS23)
    mp3_name       = rng.choice(PROHIBITED_MEDIA_NAMES)
    return {
        "scenario": "10-ubuntu-faillock",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "hidden_user": hidden_user,
        "nonadmin_user": nonadmin_user,
        "remote_group_users": remote_users,
        "prohibited_package": prohibited_pkg,
        "prohibited_mp3_path": f"/home/{nonadmin_user}/Music/{mp3_name}",
        "services_must_survive": ["sshd"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "SSH on :22 must accept TCP connections at submit time.",
                "The `remote` group must contain exactly: "
                + ", ".join(remote_users) + " (no extras, no missing).",
            ],
            "time_budget_minutes": 30,
        },
    }


def _scenario_11(rng: random.Random) -> dict:
    """HS23 — Server-Core + DC/DNS-style hardening (registry-state)."""
    base = _windows_common(rng, "11-win-dc-dns")
    base.update({
        "services_must_survive": ["admin_login"],
        "sanitized": {
            "admin_user": base["admin_user"],
            "services_must_survive": [
                "The local administrator account above must still exist and "
                "remain in the Administrators group.",
            ],
            "time_budget_minutes": 30,
        },
    })
    return base


def _scenario_12(rng: random.Random) -> dict:
    """S12 — CentOS 7 / RHEL-family LAMP."""
    admin          = rng.choice(ADMIN_NAMES)
    backdoor_user  = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    extra_uid0     = rng.choice([n for n in BACKDOOR_USER_NAMES
                                 if n not in (admin, backdoor_user)])
    nonadmin_user  = rng.choice(NONADMIN_REGULAR_NAMES)
    sudoers_drop   = rng.choice(CENTOS_SUDOERS_DROP_NAMES)
    rogue_repo     = rng.choice(CENTOS_BACKDOOR_REPO_NAMES)
    rogue_repo_url = rng.choice(CENTOS_ROGUE_YUMREPO_URLS)
    trojan_path    = rng.choice(TROJAN_TARGETS_LINUX)
    suid_plant     = rng.choice(SUID_PLANT_NAMES)
    cron_name      = rng.choice(CRON_NAMES)
    listener_port  = rng.randint(20000, 40000)
    return {
        "scenario": "12-centos7-lamp",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "backdoor_user": backdoor_user,
        "extra_uid0_user": extra_uid0,
        "nonadmin_user": nonadmin_user,
        "sudoers_drop_name": sudoers_drop,
        "rogue_yum_repo_name": rogue_repo,
        "rogue_yum_repo_url": rogue_repo_url,
        "trojan_path": trojan_path,
        "suid_plant": suid_plant,
        "cron_name": cron_name,
        "cron_path": f"/etc/cron.d/{cron_name}",
        "listener_port": listener_port,
        "services_must_survive": ["httpd", "mariadb", "sshd"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "httpd (HTTP on :80)",
                "mariadb (on :3306)",
                "sshd (on :22)",
            ],
            "time_budget_minutes": 30,
        },
    }


def _scenario_13(rng: random.Random) -> dict:
    """S13 — Windows Server 2019 AD-DC (single-domain, single-forest)."""
    admin        = rng.choice(WIN_ADMIN_NAMES)
    rogue_da     = rng.choice(AD_ROGUE_DA_NAMES)
    svc_account  = rng.choice(AD_SERVICE_ACCOUNT_NAMES)
    svc_weak_pw  = rng.choice(AD_KERBEROAST_WEAK_PASSWORDS)
    domain_fqdn  = rng.choice(AD_DOMAIN_NAMES)
    netbios      = domain_fqdn.split(".")[0].upper()
    schtask_name = rng.choice(WIN_SCHTASK_NAMES)
    return {
        "scenario": "13-ad-dc-win2019",
        "admin_user": admin,
        "admin_weak_password": "P@ssw0rd-" + str(rng.randint(1000, 9999)),
        "domain_fqdn": domain_fqdn,
        "domain_netbios": netbios,
        "dsrm_password": "DsrmP@ss-" + str(rng.randint(1000, 9999)),
        "rogue_domain_admin": rogue_da,
        "kerberoastable_svc": svc_account,
        "kerberoastable_svc_spn": f"HTTP/app1.{domain_fqdn}",
        "kerberoastable_svc_password": svc_weak_pw,
        "unconstrained_computer": "LEGACY-APP-01",
        "schtask_name": schtask_name,
        "services_must_survive": ["ad_dc", "ldap", "kerberos", "dns"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                f"AD DS must remain functional for domain {domain_fqdn}.",
                "LDAP (:389), Kerberos (:88), and DNS (:53) must respond.",
                "SYSVOL and NETLOGON shares must remain accessible to "
                "Authenticated Users.",
            ],
            "time_budget_minutes": 45,
        },
    }


def _scenario_14(rng: random.Random) -> dict:
    """S14 — FreeBSD 13 (pf/rc.conf/pkg-audit stack)."""
    admin         = rng.choice(ADMIN_NAMES)
    backdoor_user = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    periodic_name = rng.choice(BSD_PERIODIC_DROP_NAMES)
    kld_name      = rng.choice(BSD_KLD_MODULE_NAMES)
    rogue_pkg     = rng.choice(BSD_ROGUE_PKG_NAMES)
    trojan_path   = rng.choice([
        "/usr/local/bin/sysmon", "/usr/local/sbin/netcheck",
        "/usr/local/libexec/updater",
    ])
    listener_port = rng.randint(20000, 40000)
    return {
        "scenario": "14-freebsd13",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "backdoor_user": backdoor_user,
        "periodic_drop_name": periodic_name,
        "periodic_drop_path":
            f"/usr/local/etc/periodic/daily/{periodic_name}",
        "kld_module_name": kld_name,
        "rogue_pkg_name": rogue_pkg,
        "trojan_path": trojan_path,
        "listener_port": listener_port,
        "services_must_survive": ["sshd", "nginx"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "sshd on :22 must accept connections at submit time.",
                "nginx must respond on :80 at submit time.",
            ],
            "time_budget_minutes": 30,
        },
    }


def _scenario_15(rng: random.Random) -> dict:
    """S15 — Docker host hardening (dockerd-in-container)."""
    admin            = rng.choice(ADMIN_NAMES)
    backdoor_user    = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    workload_image   = rng.choice(["nginx:1.25", "httpd:2.4", "caddy:2"])
    backdoor_image   = rng.choice(DOCKER_BACKDOOR_IMAGES)
    backdoor_cname   = rng.choice(DOCKER_BACKDOOR_CONTAINER_NAMES)
    insecure_reg     = rng.choice(DOCKER_INSECURE_REGISTRIES)
    tcp_port         = rng.choice([2375, 2376, 4243])
    return {
        "scenario": "15-docker-host",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "backdoor_user": backdoor_user,
        "workload_image": workload_image,
        "workload_container_name": "app-web",
        "backdoor_image": backdoor_image,
        "backdoor_container_name": backdoor_cname,
        "insecure_registry": insecure_reg,
        "dockerd_tcp_port": tcp_port,
        "services_must_survive": ["sshd", "workload_http"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "sshd on :22 must accept connections at submit time.",
                "The workload container's HTTP endpoint on :8080 must respond "
                "with a 2xx or 3xx response at submit time.",
            ],
            "time_budget_minutes": 30,
        },
    }


def _scenario_16(rng: random.Random) -> dict:
    """S16 — Debian 12 + nginx + PHP-FPM."""
    admin         = rng.choice(ADMIN_NAMES)
    backdoor_user = rng.choice([n for n in BACKDOOR_USER_NAMES if n != admin])
    webshell_name = rng.choice(NGINX_WEBSHELL_NAMES)
    private_vhost = rng.choice(NGINX_VHOST_NAMES)
    trojan_path   = rng.choice(TROJAN_TARGETS_LINUX)
    cron_name     = rng.choice(CRON_NAMES)
    listener_port = rng.randint(20000, 40000)
    return {
        "scenario": "16-nginx-phpfpm",
        "admin_user": admin,
        "admin_weak_password": "changeme-" + str(rng.randint(1000, 9999)),
        "backdoor_user": backdoor_user,
        "webshell_name": webshell_name,
        "webshell_path": f"/var/www/uploads/{webshell_name}",
        "private_vhost_name": private_vhost,
        "trojan_path": trojan_path,
        "cron_name": cron_name,
        "cron_path": f"/etc/cron.d/{cron_name}",
        "listener_port": listener_port,
        "services_must_survive": ["nginx", "phpfpm", "sshd"],
        "sanitized": {
            "admin_user": admin,
            "services_must_survive": [
                "nginx on :80 must serve the public vhost at submit time.",
                "PHP-FPM must be running and reachable via the local socket.",
                "sshd on :22 must accept connections at submit time.",
            ],
            "time_budget_minutes": 30,
        },
    }


SCENARIOS = {
    "01": _scenario_01,
    "02": _scenario_02,
    "03": _scenario_03,
    "04": _scenario_04,
    "05": _scenario_05,
    "06": _scenario_06,
    "07": _scenario_07,
    "08": _scenario_08,
    "09": _scenario_09,
    "10": _scenario_10,
    "11": _scenario_11,
    "12": _scenario_12,
    "13": _scenario_13,
    "14": _scenario_14,
    "15": _scenario_15,
    "16": _scenario_16,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build(scenario: str, seed: int) -> dict:
    if scenario not in SCENARIOS:
        raise SystemExit(f"Unknown scenario '{scenario}'. Known: {sorted(SCENARIOS)}")
    rng = random.Random(seed)
    roles = SCENARIOS[scenario](rng)
    roles["_seed"] = seed
    return roles


def render_task(template_path: Path, roles: dict) -> str:
    tmpl = template_path.read_text(encoding="utf-8")
    sanitized = roles["sanitized"]
    services = "\n".join(f"    - {s}" for s in sanitized["services_must_survive"])
    return tmpl.format(
        admin_user=sanitized["admin_user"],
        services_list=services,
        time_budget_minutes=sanitized["time_budget_minutes"],
    )


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", required=True,
                   help="Scenario id, e.g. '01'")
    p.add_argument("--seed", type=int, default=None,
                   help="RNG seed. Omit for os.urandom-based seed.")
    p.add_argument("--out", type=Path, required=True,
                   help="Path to write roles.json")
    p.add_argument("--render-task", type=Path, default=None,
                   help="If set, render task.md from task.md.tmpl sibling at "
                        "this path.")
    args = p.parse_args(argv)

    seed = args.seed
    if seed is None:
        seed = int.from_bytes(__import__("os").urandom(4), "big")

    roles = build(args.scenario, seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(roles, indent=2) + "\n", encoding="utf-8")
    print(f"roles -> {args.out} (seed={seed})", file=sys.stderr)

    if args.render_task is not None:
        tmpl = args.render_task.with_suffix(".md.tmpl") if args.render_task.suffix == ".md" \
            else Path(str(args.render_task) + ".tmpl")
        if not tmpl.exists():
            tmpl = args.render_task.parent / "task.md.tmpl"
        rendered = render_task(tmpl, roles)
        args.render_task.write_text(rendered, encoding="utf-8")
        print(f"task -> {args.render_task}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
