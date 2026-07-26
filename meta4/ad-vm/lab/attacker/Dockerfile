# SysRepair-Bench attacker tooling image.
#
# Replaces provision/attacker-baseline.sh, which was broken in a way that
# silently invalidated most of the AD suite:
#
#   * It pip-installed impacket into a venv and symlinked names like
#     `impacket-GetUserSPNs`. pip installs `GetUserSPNs.py` instead -- the
#     `impacket-` prefix is a Kali packaging convention -- so every
#     `[ -f ... ]` guard was false and every symlink was silently skipped.
#   * It symlinked into /usr/local/bin while all 20 verify-poc.sh call /usr/bin.
#   * It guarded on `certipy-ad`; pip's certipy-ad installs `certipy`.
#   * responder, hashcat and freerdp were never installed at all.
#
# Combined effect: verify-poc.sh invoked binaries that could not exist,
# `|| true` swallowed the error, and the fail-open terminal branches graded
# "PoC BLOCKED" -- a PASS on an unmodified vulnerable box.
#
# Everything below comes from Kali's own packages where one exists. Nothing is
# pip-installed: apt provides correct binary names for every tool the scenarios
# call, including certipy-ad, and avoids a venv whose Python version can break
# a package's imports.
#
# BUILD WITH --network host WHEN BUILDING ON attacker01:
#
#     sudo docker build --network host -t srb-attacker:1 .
#
# /etc/docker/daemon.json pins container DNS to the domain controller
# (10.20.30.5). That is correct at RUNTIME -- the container runs with
# --network host on an isolated segment and must resolve corp.local -- but at
# BUILD time the DC cannot resolve Kali's repositories. Without --network host
# the build fails in a way that names no cause: `apt-get update` succeeds
# against nothing and every package reports "Unable to locate package",
# including basics like nmap and git. --network host lets the build use the
# VM's own resolver instead.
FROM kalilinux/kali-rolling@sha256:dea2bdf0e8c0ca1deb51b7a6253f481acae3ca9c2f1e2371077e6af55e5b2721

ENV DEBIAN_FRONTEND=noninteractive

# impacket-scripts provides the /usr/bin/impacket-* names the scenarios call.
# python3-impacket alone ships only five of them, which is why the old
# provisioner appeared to half-work.
# certipy-ad provides /usr/bin/certipy-ad directly -- scenarios 07-10's exact
# path and name.
# hashcat (S03, S04), responder (S14) and freerdp3-x11 (S19) were absent from
# the old provisioner entirely.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      impacket-scripts certipy-ad \
      netexec bloodhound.py \
      responder freerdp3-x11 hashcat \
      nmap ldap-utils smbclient krb5-user \
      git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Kali installs responder at /usr/sbin/responder (it is a root tool), but
# scenario-14/verify-poc.sh:14 calls /usr/bin/responder. Shim rather than edit
# the scenario, keeping this phase's diff inside the image.
RUN ln -sf /usr/sbin/responder /usr/bin/responder

# Three tools the scenarios call exist in no package at any version:
# zerologon_tester (S01), spoolsample (S16) and PetitPotam (S17). They come
# from upstream research repos, pinned by commit so a reviewer resolves the
# same code. Wrapper names match what the scenarios already invoke.
#
# NOTE for phase 4a: shipping these makes the tools resolve, but S01 and S16
# still need redesign. S16 in particular grades the wrong vulnerability --
# printerbug.py is MS-RPRN coercion (PrinterBug), while scenario-16/threat.md
# describes RpcAddPrinterDriverEx (PrintNightmare), so two of its three
# documented remediations cannot pass. Resolving the binary does not resolve
# that.
ARG ZEROLOGON_SHA=93b7e276c2fea9a4149a631c0d359f9b45dc45a9
ARG PETITPOTAM_SHA=c5d5221dc5e6aac3bc7de97a34fa8d89c2f1900b
ARG KRBRELAYX_SHA=10b45a33bc4361ec4a5546eea62db2e4244d3255

RUN set -eux; \
    mkdir -p /opt/ext; \
    git clone -q https://github.com/SecuraBV/CVE-2020-1472 /opt/ext/zerologon; \
    git -C /opt/ext/zerologon checkout -q "${ZEROLOGON_SHA}"; \
    git clone -q https://github.com/topotam/PetitPotam /opt/ext/petitpotam; \
    git -C /opt/ext/petitpotam checkout -q "${PETITPOTAM_SHA}"; \
    git clone -q https://github.com/dirkjanm/krbrelayx /opt/ext/krbrelayx; \
    git -C /opt/ext/krbrelayx checkout -q "${KRBRELAYX_SHA}"; \
    rm -rf /opt/ext/*/.git

RUN set -eux; \
    printf '#!/bin/sh\nexec python3 /opt/ext/zerologon/zerologon_tester.py "$@"\n' \
      > /usr/bin/impacket-zerologon_tester; \
    printf '#!/bin/sh\nexec python3 /opt/ext/petitpotam/PetitPotam.py "$@"\n' \
      > /usr/bin/impacket-PetitPotam; \
    printf '#!/bin/sh\nexec python3 /opt/ext/krbrelayx/printerbug.py "$@"\n' \
      > /usr/bin/impacket-spoolsample; \
    chmod 755 /usr/bin/impacket-zerologon_tester \
              /usr/bin/impacket-PetitPotam \
              /usr/bin/impacket-spoolsample

COPY krb5.conf /etc/krb5.conf

# Build-time gate. Every tool any verify-poc.sh invokes must not merely EXIST
# but actually RUN and produce output.
#
# An existence check is not enough. certipy-ad installed from pip passes
# `test -x` and then dies at import on Python 3.13 because pkg_resources is
# gone -- a crash the scenarios' `|| true` would swallow and grade as "PoC
# BLOCKED". That is the exact defect class this image exists to eliminate.
#
# The gate keys on interpreter-level import failures and on empty output.
# It deliberately tolerates a non-empty traceback that still yields usage
# text: krbrelayx's printerbug.py emits a cosmetic logging-format traceback
# under Python 3.13 while remaining functional. Empty output is fatal --
# a tool that cannot even print usage cannot run an attack.
#
# The tool list is generated by lab/Get-ScenarioToolPaths.ps1 -- regenerate it
# when a scenario adds a dependency.
RUN set -eu; \
    fail=0; \
    for t in /usr/bin/certipy-ad \
             /usr/bin/impacket-addcomputer \
             /usr/bin/impacket-changepasswd \
             /usr/bin/impacket-describeTicket \
             /usr/bin/impacket-GetNPUsers \
             /usr/bin/impacket-getST \
             /usr/bin/impacket-GetUserSPNs \
             /usr/bin/impacket-net \
             /usr/bin/impacket-PetitPotam \
             /usr/bin/impacket-rpcdump \
             /usr/bin/impacket-secretsdump \
             /usr/bin/impacket-spoolsample \
             /usr/bin/impacket-zerologon_tester \
             /usr/bin/responder \
             /usr/bin/hashcat \
             /usr/bin/xfreerdp; do \
        if [ ! -x "$t" ]; then \
            echo "TOOL GATE: $t is not executable" >&2; fail=1; continue; \
        fi; \
        out=$("$t" --help 2>&1 </dev/null || true); \
        if [ -z "$out" ]; then \
            echo "TOOL GATE: $t produced no output" >&2; fail=1; continue; \
        fi; \
        case "$out" in \
            *ModuleNotFoundError*|*ImportError*|*"No module named"*) \
                echo "TOOL GATE: $t fails at import:" >&2; \
                echo "$out" | grep -E 'Error|No module' | head -2 >&2; \
                fail=1 ;; \
        esac; \
    done; \
    [ "$fail" -eq 0 ] || { echo "TOOL GATE FAILED" >&2; exit 1; }; \
    echo "tool gate: all 16 scenario dependencies resolve AND execute"

CMD ["/bin/bash"]
