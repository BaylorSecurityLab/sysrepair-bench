# scenario-14-freebsd13 — divergent invocation

Unlike the Docker-native scenarios, this one is a **Vagrant VM**: FreeBSD
cannot run inside a Linux container (different kernel ABI, `pf` lives in
the kernel, `kldload` requires a real kernel, `rc.d` expects the FreeBSD
init). It follows the same VM pattern as `meta3/windows/` and
`scenario-13-ad-dc-win2019`.

## Prereqs

- Vagrant ≥ 2.3
- VirtualBox ≥ 6.1 (or libvirt; `Vagrantfile` uses the VirtualBox provider
  by default, edit to switch)
- The `freebsd/FreeBSD-13.2-RELEASE` box (Vagrant Cloud)

## Build flow

```bash
# 1. Generate roles.json + render task.md (same as Docker scenarios)
hivestorm/prepare.sh 14

# 2. Bring up the VM — provisioner installs nginx, then runs seed.sh
cd hivestorm/scenario-14-freebsd13
vagrant up
```

First boot takes ~5–8 minutes (package install + seed). Subsequent
`vagrant up` of a previously provisioned VM skips the provisioner.

## Running the verifier

The Inspect-AI harness invokes `verify.sh` over SSH. For manual runs:

```bash
vagrant ssh -c 'sudo /var/db/sysrepair/verify.sh'
```

JSONL output is captured and scored by `hivestorm_weighted_scorer`.

## Scope caveats

- **FreeBSD-specific toolchain only.** `pf`, `rc.conf`, `kldstat`,
  `periodic`, `pkg audit` are the primitives the agent must know. A
  Linux-centric approach (iptables, systemctl, apt) will fail.
- **pkg audit** runs against the live vulnxml feed. The seeder installs
  a deliberately old `rogue_pkg` name — the agent is credited for either
  removing it or for upgrading it via `pkg upgrade`.
- **No ZFS** requirements. The box defaults to UFS; ZFS-specific
  hardening (dataset ACLs, snapshots) is out of scope for this scenario.
