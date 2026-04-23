# SysRepair-Bench: Metasploitable 4 Sub-Suite

## Overview

Container scenarios covering **modern (2021–2026) vulnerabilities** that neither Metasploitable 2 nor Metasploitable 3 exercise. Meta4 is the "next-generation" track: Log4Shell-era Java RCE, cloud-native supply-chain flaws, container-runtime escapes, modern Linux LPE chains, and vulnerable API/GraphQL stacks. See the [root README](../README.md) for benchmark-wide overview, scenario format, and host setup.

## No-overlap policy

Each scenario targets a CVE or misconfiguration **not already covered** by `meta2/`, `meta3/ubuntu/`, `meta3/windows/`, `ccdc/`, or `vulnhub/`. Specifically excluded:

- Classic Tomcat/Struts/Jenkins/ManageEngine/ElasticSearch/GlassFish/Axis2 (meta3/windows S04–S09, S16)
- SMBv1/EternalBlue, SMB signing, RDP-NLA, LLMNR/NBT-NS, unquoted service path (meta3/windows S10–S14)
- ProFTPD mod_copy, Drupageddon, Shellshock, WEBrick, payroll credential reuse (meta3/ubuntu S06, S07, S10–S19)
- SSH weak KEX/host-key, CUPS TLS, SNMP public (already in meta3 S01–S04)
- vsftpd 2.3.4, UnrealIRCd, Samba usermap, ingreslock, distcc, MySQL empty root, PostgreSQL weak auth, Debian OpenSSL PRNG, TWiki, TikiWiki, Mutillidae, DVWA, NFS root export (meta2)

## Scope

**In scope (container-native, modern-CVE layer):**
- Java ecosystem RCE: Log4Shell family, Spring4Shell, Spring Cloud Function SpEL
- Modern web-server / app-server CVEs (Apache 2.4.49/50 traversal, Tomcat 2024–2025 deserialization & race)
- Enterprise SaaS stack RCE in self-hosted editions (Confluence 7.18 OGNL & 2023 broken auth, GitLab 16.7 takeover)
- CI/CD pipeline RCE (Jenkins 2.441 arg-injection, TeamCity auth bypass)
- Modern Linux LPE (PwnKit, Baron Samedit, Dirty Pipe, Looney Tunables, GameOver(lay), nf_tables UAF)
- Container / runtime escapes (Leaky Vessels runc, BuildKit CVE-2024-23651/52/53, docker.sock mount, `--privileged` escape)
- Supply-chain forensics (XZ Utils 5.6.1 backdoor — CVE-2024-3094)
- OpenSSH modern flaws (regreSSHion CVE-2024-6387, Terrapin CVE-2023-48795)
- Vulnerable-by-design API surfaces (OWASP crAPI, DVGA GraphQL, VAmPI REST)
- Cloud-on-localhost misconfigurations (LocalStack IMDS SSRF, MinIO public buckets, ArgoCD default Redis, k3s insecure defaults)
- WordPress 2024 auth bypass (CVE-2024-10924) — distinct from meta3 WAMP/WP stack

**Out of scope:**
- Anything already in meta2/meta3/ccdc/vulnhub (see list above)
- Pure Active Directory attacks (Zerologon, PrintNightmare, PetitPotam, noPac, Certifried, AD CS ESC1–ESC8) — these require a multi-VM Windows domain and are tracked separately as **Meta4-AD** (VM-based, not containerized); see plan doc
- Source-code-only fixes — remediation must be sys-admin layer (patch, config, segmentation, compensating control)

## Base images

| Family | Base | Notes |
|---|---|---|
| Java RCE | `openjdk:11-jdk-slim`, `tomcat:9.0.60-jdk11` | pinned pre-patch |
| Apache httpd | `httpd:2.4.49`, `httpd:2.4.50` | official vulnerable tags |
| Confluence / GitLab | `atlassian/confluence-server:7.18.0`, `gitlab/gitlab-ce:16.7.0-ce.0` | vendor-published images |
| Linux LPE | `ubuntu:22.04`, `ubuntu:20.04` | kernel LPEs require privileged runtime + matching host kernel; documented per scenario |
| Container escape | `docker:24-dind` with `runc 1.1.11` | Leaky Vessels reproduction |
| XZ forensics | `debian:testing-20240301` | tarball-sourced xz 5.6.1 |
| API targets | upstream crAPI / DVGA / VAmPI compose stacks | vendored |
| Cloud sim | `localstack/localstack:3`, `minio/minio`, `argoproj/argocd`, `rancher/k3s` | |

## Host-kernel coupling

Three scenarios target kernel vulnerabilities and therefore need a host whose kernel matches the vulnerable ABI — see [`kernel-vm/`](kernel-vm/) for the Vagrant VM. All three also accept a **compensating control** (`chattr +i` for S19, `kernel.unprivileged_userns_clone=0` for S21/S22) which is host-kernel-agnostic.

| ID | CVE | Vulnerable kernel | Covered by kernel-vm? |
|---|---|---|---|
| [scenario-19](scenario-19/) — Dirty Pipe | CVE-2022-0847 | 5.8 – 5.16.10 | No — needs Ubuntu 20.04 HWE 5.13.0-27 or earlier |
| [scenario-21](scenario-21/) — GameOver(lay) | CVE-2023-2640 / 32629 | Ubuntu 5.15.0 ABI < 75 | Yes |
| [scenario-22](scenario-22/) — `nf_tables` UAF | CVE-2024-1086 | Ubuntu 5.15.0 ABI < 97 | Yes |

All other scenarios run on any modern Linux Docker host — the vulnerable component lives in userspace (libc, polkit, sudo, runc, application jars, plugin code). Notably [scenario-11](scenario-11/) (regreSSHion) and [scenario-20](scenario-20/) (Looney Tunables) are glibc/sshd userspace issues despite sometimes being described as "system-level".
