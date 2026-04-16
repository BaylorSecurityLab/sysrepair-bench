# Kernel-LPE Vagrant VM

This directory provisions a VirtualBox VM with a **pinned vulnerable
Ubuntu 22.04 kernel** and Docker pre-installed. The three kernel-level
LPE scenarios run as containers inside this VM so they share its
vulnerable kernel.

## Quick start

```bash
cd meta4/kernel-vm
vagrant up          # provisions VM, installs Docker, pins kernel
vagrant ssh

# Inside the VM — scenario directories are mounted at /meta4
cd /meta4

# Build and test a kernel scenario (should FAIL before remediation)
docker build -t s21 scenario-21
docker run --rm --privileged s21 bash /verify.sh

# Apply remediation inside the container, then re-run verify
```

## Kernel coverage matrix

| Scenario | CVE | Kernel fix | Covered by this VM? |
|---|---|---|---|
| S19 Dirty Pipe | CVE-2022-0847 | 5.15.0-25.25 (pre-GA) | **No** — 22.04 GA already includes the fix |
| S21 GameOverlay | CVE-2023-2640/32629 | 5.15.0-75 | **Yes** — VM pins ABI < 75 |
| S22 nf_tables UAF | CVE-2024-1086 | 5.15.0-97 | **Yes** — VM pins ABI < 97 |

## S19 (Dirty Pipe) — separate host required

Dirty Pipe was patched before Ubuntu 22.04 reached GA. To reproduce it
you need an Ubuntu **20.04** host running the HWE kernel **5.13.0-27**
or earlier (pre-USN-5317-1, February 2022):

```bash
# Example: Vagrant box with Ubuntu 20.04
vagrant init ubuntu/focal64 --box-version "~> 20220101"
vagrant up && vagrant ssh

# Inside the 20.04 VM, install Docker and run S19
sudo apt-get install -y docker.io
sudo docker build -t s19 /path/to/meta4/scenario-19
sudo docker run --rm --privileged s19 bash /verify.sh
```

Alternatively, run S19 in **compensating-control mode** on any host:
the agent applies `chattr +i /opt/suid-marker` and verify.sh accepts
that regardless of host kernel version.

## Container runtime flags

Kernel-LPE scenarios need elevated container privileges to interact with
the host kernel:

```bash
# GameOverlay requires user namespaces (default on Ubuntu)
docker run --rm --privileged s21 bash /verify.sh

# nf_tables requires CAP_NET_ADMIN (for nftables access)
docker run --rm --cap-add=NET_ADMIN s22 bash /verify.sh
```

## Tearing down

```bash
vagrant destroy -f
```
