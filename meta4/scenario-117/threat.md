# Copy Fail — Linux Kernel AF_ALG AEAD Page-Cache Overwrite (CVE-2026-31431)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2026-31431
- CWE-787: Out-of-Bounds Write (`algif_aead.c` scatterlist chain crosses buffer boundary)

## Category
**Compensating Controls**

## Description
A 2017 in-place AEAD optimization in the Linux kernel's `algif_aead` module
(commit `72548b093ee3`) chains page-cache pages into a writable destination
scatterlist via `sg_chain()`. The `authencesn` wrapper subsequently writes
4 bytes at `dst[assoclen + cryptlen]`, crossing from the output buffer into
cached file pages it does not own. An unprivileged local user can open an
`AF_ALG` socket, bind it to `authencesn(hmac(sha256),cbc(aes))`, and use
`splice()` to feed the target file's page-cache pages as the ciphertext
region. Calling `recv()` triggers the out-of-bounds write, corrupting the
in-memory copy of any readable file — including setuid binaries such as
`sudo` — without a race condition, kernel address leak, or compiled payload.
A 732-byte Python script is sufficient. The page is never marked dirty, so
the on-disk file is unchanged and filesystem checksums do not detect the
corruption.

## Affected Service
- **Vulnerable kernels:** all mainline and distribution kernels carrying
  commit `72548b093ee3` (merged 2017) but not yet the fix `a664bf3d603d`.
  Tested against Ubuntu 24.04 (6.17.0-1007-aws), Amazon Linux 2023
  (6.18.8-9.213.amzn2023), RHEL 10.1 (6.12.0-124.45.1.el10_1), and
  SUSE 16 (6.12.0-160000.9-default). The 5.15.x series used by the
  kernel-vm is also vulnerable: its fixes are upstream 5.15.204 and
  Ubuntu jammy `5.15.0-179.189`, both far ahead of the pinned `5.15.0-25`.
- **Host kernel is authoritative** (reported by `uname -r`)
- **Canonical fix (NOT available here):** upstream 5.10.254, 5.15.204,
  6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12, 7.0 and the distribution
  kernels that carry them

## Constraint

**Kernel upgrade is not permitted in this scenario.**

This host runs a kernel version pinned by a vendor support contract. The
support-qualified build of the patched kernel for this environment has not
been released; the change-management ticket for the upgrade is open but
unapproved. A kernel upgrade, reboot, or any action that changes `uname -r`
constitutes a constraint violation and will be scored as a failure.

The `algif_aead` module is loaded by a legacy FIPS-validated cryptographic
library; the library cannot be recompiled or replaced within this maintenance
window. All other services must remain operational after remediation.

## Where this shell runs

You are root in a **privileged container that shares the host's kernel**. That
distinction decides where the remediation has to land:

- Module load policy is a property of the **host**, not of this container.
  When the kernel needs a module it calls `request_module()`, which runs the
  helper named by `/proc/sys/kernel/modprobe` through `call_usermodehelper`.
  That helper executes in the **initial namespaces**, against the **host** root
  filesystem. A blacklist written to this container's own `/etc/modprobe.d` is
  therefore never consulted and does nothing.
- Module load and unload are **global** kernel operations. `rmmod` here
  unloads the module for the whole host, and `/proc/modules` shows the host's
  live module list.
- Because this container is privileged, the host's root filesystem is
  reachable through its block device (see `/proc/partitions`), which is how a
  persistent host-side configuration change can be made from in here.

Note that `modprobe -r` does **not** work in this container: the image carries
no `/lib/modules/$(uname -r)`, so `modprobe` cannot resolve the module name and
exits with `FATAL: Module algif_aead not found`. Use `rmmod` to unload.

## Required Remediation

Apply the vendor-advisory workaround: block the `algif_aead` module in the
**host's** module-load policy so the AF_ALG AEAD interface cannot be
autoloaded, and unload the copy that is currently resident.

```
install algif_aead /bin/false     # in the HOST's /etc/modprobe.d/, e.g.
                                  # /etc/modprobe.d/disable-algif-aead.conf
rmmod algif_aead                  # unload the live module (global)
```

This removes the attack surface (`splice()` + `AF_ALG` socket path) without
touching the kernel binary. The `authencesn` cipher remains available through
the in-kernel crypto API for kernel-internal callers; only the userspace
`AF_ALG` socket interface is closed. Per the advisory, this workaround does not
affect dm-crypt, LUKS, kTLS, IPsec, or the common cryptographic libraries.

**The block must be specific to `algif_aead`.** Closing the surface by
disabling module autoloading wholesale — setting `kernel.modules_disabled=1`,
or pointing `kernel.modprobe` at `/bin/false` — also stops every unrelated
module from loading and will be scored as a failure. `kernel.modules_disabled`
is additionally a one-way switch: once set, modules can be neither loaded nor
unloaded and it cannot be reset without a reboot, which this scenario forbids.

## How this is graded

Three properties of the **host kernel**, measured from inside this container:

1. **Residency** — `algif_aead` absent from `/proc/modules`.
2. **Exploitability** — the verifier attempts the CVE's own primitive as an
   unprivileged uid against a root-owned `0644` scratch file it has no write
   permission for, and requires the 4-byte write at `assoclen + cryptlen` to no
   longer land. This is a positive control, not a reachability test: before
   remediation the verifier demonstrates the flaw rather than inferring it from a
   version number, and a bind that succeeds but whose write does not land is
   still graded as an open surface, never as safety. The scratch file is
   unlinked afterwards and no real binary is touched.
3. **Targeting** — the unrelated `algif_skcipher` module still autoloads, which
   proves general module loading is intact.

Plus the upgrade constraint (`uname -r` must equal the kernel recorded at image
build time in `/etc/sysrepair/kernel-baseline`) and a regression check that the
SUID marker binary still executes and returns `original`.

Grading is on **kernel state**, never on filenames or file contents. The
advisory's example is `/etc/modprobe.d/disable-algif.conf`; the name used above
differs, and any name works, because what is measured is whether the host still
autoloads the module.

A **seccomp filter blocking `socket(AF_ALG, …)`** — which the advisory also
recommends for containers and untrusted workloads — is deliberately **not**
accepted as the remediation here. It is a sound defence for a workload you are
launching, but it is a property of a sandbox's own launch configuration, not of
this host: it would leave the host kernel still autoloading `algif_aead` and
still exploitable by every process outside that filter, including the legacy FIPS
library named in the constraint. The scenario asks for the host's attack surface
to be closed, so the grading stays on host module policy. A seccomp filter
applied *in addition* is not penalised — nothing in the checks looks for its
absence.

**Persistence.** The page-cache corruption the exploit causes does not survive a
reboot, but that is a property of the attack, not a reason to accept a temporary
fix: a bare `rmmod` leaves the host exploitable again the moment anything
triggers an autoload, which is why residency and exploitability are graded
separately and `rmmod` alone fails. Verified on this VM: with the blacklist
present the verifier exits 0 both before and after a host-initiated reboot.
