# hivestorm/ — free-roam SysRepair scenarios

Hivestorm-style scenarios. Unlike `meta2/`, `meta3/`, `meta4/`, `ccdc/`, and
`vulnhub/`, the agent is **not told what is wrong**. Each container has
multiple independent issues across user management, PAM, sysctl, service
hardening, backdoors, and package hygiene. The agent enumerates and
remediates without a CVE briefing or category hint.

Source material:
- Hivestorm 2020 — https://sourque.com/ctf/hivestorm/hs20/ (scenarios 01-05)
- Hivestorm 2021 — https://sourque.com/ctf/hivestorm/hs21/ (scenarios 06-08)
- Hivestorm 2023 — https://systemfailu.re/2023/10/19/hivestorm-2023-writeup/ (scenarios 09-11)

Forensics tasks are intentionally excluded; this suite is sysrepair-focused.

Design docs:
- [../docs/HIVESTORM_PLAN.md](../docs/HIVESTORM_PLAN.md) — HS20 (01-05)
- [../docs/HIVESTORM_HS21_PLAN.md](../docs/HIVESTORM_HS21_PLAN.md) — HS21 (06-08)
- [../docs/HIVESTORM_HS23_PLAN.md](../docs/HIVESTORM_HS23_PLAN.md) — HS23 (09-11)

## Anti-memorization

Every identity the agent could otherwise memorize across runs (backdoor
account name, trojaned binary path, rogue cron filename, SUID plant path,
listener port, *and the legit admin username*) is randomized at build time
by [common/roles.py](common/roles.py). Only the sanitized subset (legit
admin + service-survival list) leaks into the agent-facing `task.md`.

The full role-map is written to `/etc/sysrepair/roles.json` inside the
container, chmod 0600 root-owned. The scorer reads it from inside the
sandbox to know what to check for.

## Build flow

Before running the eval, regenerate roles + prompts:

```bash
# one scenario, random seed
hivestorm/prepare.sh 01

# reproducible
SEED=42 hivestorm/prepare.sh 01

# all implemented scenarios
hivestorm/prepare.sh
```

`prepare.sh` writes:

- `<scenario>/build/roles.json` — consumed by Dockerfile COPY + seed.sh
- `<scenario>/task.md` — rendered from `task.md.tmpl`, read by the harness

Both are `.gitignore`d; only the templates are committed.

Then run the eval as normal, restricting to hivestorm scenarios:

```bash
cd inspect_eval
uv run python -m sysrepair_bench.run <preset> \
    # with the preset's `benchmarks: [hivestorm]` or
    # `scenarios: [hivestorm/scenario-01-debian9]`
```

## Scoring

Weighted partial credit via [inspect_eval/sysrepair_bench/scorer.py](../inspect_eval/sysrepair_bench/scorer.py):
`hivestorm_weighted_scorer` parses JSONL lines emitted by `verify.sh` and
computes `(raw - service_penalty) / total`. Full per-check breakdown is
preserved in `Score.metadata["checks"]`.

Per-sample scorer selection is driven by `metadata["scorer"]`, set by
`_build_sample` in [task.py](../inspect_eval/sysrepair_bench/task.py) when
`benchmark == "hivestorm"`. meta2/3/4/ccdc/vulnhub remain on the binary
scorer unchanged.

## Status

| ID | Base | Status |
|---|---|---|
| scenario-01-debian9             | `debian:9` (archive.debian.org)         | implemented |
| scenario-02-ubuntu1604          | `ubuntu:16.04` (old-releases)           | implemented |
| scenario-03-win10               | `servercore:ltsc2019` (Win10 stand-in)  | implemented |
| scenario-04-win2019             | `servercore:ltsc2019`                   | implemented |
| scenario-05-win2016             | `servercore:ltsc2016`                   | implemented |
| scenario-06-debian9-postgres    | `debian:9` + PostgreSQL (HS21)          | implemented |
| scenario-07-ubuntu1804-samba    | `ubuntu:18.04` + Samba (HS21)           | implemented |
| scenario-08-win-iis             | `servercore/iis:ltsc2019` + PHP (HS21)  | implemented |
| scenario-09-ubuntu-nginx-phpbb  | `ubuntu:20.04` + nginx + persistence (HS23) | implemented |
| scenario-10-ubuntu-faillock     | `ubuntu:22.04` + faillock + group hygiene (HS23) | implemented |
| scenario-11-win-dc-dns          | `servercore:ltsc2019` + DC/DNS reg-state (HS23) | implemented |
| scenario-12-centos7-lamp        | `centos:7` (vault.centos.org)           | implemented |
| scenario-13-ad-dc-win2019       | Win2019 Vagrant VM (ADDS promoted)      | implemented (VM) |
| scenario-14-freebsd13           | FreeBSD 13 Vagrant VM                   | implemented (VM) |
| scenario-15-docker-host         | `ubuntu:22.04` + dockerd-in-container   | implemented |
| scenario-16-nginx-phpfpm        | `debian:12` + nginx + php8.2-fpm        | implemented |

Win10 has no public Docker client image; scenario-03 degrades to Server-Core
2019 as a stand-in (documented in the HS20 plan).

Windows containers cannot run the full service surface area of a real host
(Server-Core can't host Print Spooler, Telnet-Server, SMB server). Windows
scenarios (03/04/05/08/11) score on registry / policy / file state rather than
live service behavior; the `services_must_survive` probes check account and
IIS state only.

Scenarios 13 (AD-DC) and 14 (FreeBSD) require Vagrant: Active Directory
Domain Services cannot be hosted in a Windows Server-Core container, and
FreeBSD has no Docker image. They follow the `meta3/windows/` VM pattern and
each ships a per-scenario `README.md` documenting the divergent invocation.
