# Kernel-LPE Vagrant VM

VirtualBox VM with a **pinned vulnerable Ubuntu 22.04 kernel** and Docker pre-installed. The three kernel-level LPE scenarios run as containers inside this VM so they share its vulnerable kernel.

Host prerequisites: see the [root README §3d](../../README.md). On Linux hosts running KVM/libvirt, VirtualBox fights for `/dev/kvm` — stop `libvirtd` or wire up a `:libvirt` provider.

## Quick start

```bash
cd meta4/kernel-vm
vagrant up          # provisions VM, installs Docker, pins kernel
vagrant ssh
cd /meta4           # scenario dirs are mounted here
docker build -t s21 scenario-21
docker run --rm --privileged s21 bash /verify.sh    # FAIL before remediation
# ...remediate, re-run verify, then: vagrant destroy -f
```

## Kernel coverage

| Scenario | CVE | Kernel fix | Covered? |
|---|---|---|---|
| S19 Dirty Pipe | CVE-2022-0847 | 5.15.0-25.25 (pre-GA) | No — 22.04 GA already patched |
| S21 GameOverlay | CVE-2023-2640/32629 | 5.15.0-75 | Yes — VM pins ABI < 75 |
| S22 nf_tables UAF | CVE-2024-1086 | 5.15.0-97 | Yes — VM pins ABI < 97 |

### S19 reproduction

S19 needs a separate Ubuntu 20.04 HWE host on kernel 5.13.0-27 or earlier (pre-USN-5317-1):

```bash
vagrant init ubuntu/focal64 --box-version "~> 20220101"
vagrant up && vagrant ssh
sudo apt-get install -y docker.io
sudo docker build -t s19 /path/to/meta4/scenario-19
sudo docker run --rm --privileged s19 bash /verify.sh
```

Or run S19 in **compensating-control mode** on any host: the agent applies `chattr +i /opt/suid-marker` and verify.sh accepts that regardless of host kernel.

Kernel-LPE scenarios require `--privileged` — Docker's default seccomp profile blocks `unshare -U` from unprivileged users, so the behavioral probe needs the flag to reach actual host-kernel userns behavior.
