FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN a2enmod cgi

# ---------------------------------------------------------------------------
# Make CVE-2014-6271 (Shellshock) GENUINELY PRESENT.
#
# SCENARIO-DESIGN FIX: this image previously shipped Debian 11's patched bash
# (5.1.4) while the Dockerfile itself noted "Debian 10 bash is patched, but the
# CGI setup mirrors the vulnerable config". The PoC therefore could never fire -
# `env x='() { :;}; echo vulnerable' bash -c "echo test"` printed only "test" on
# an untouched container - so a model that did nothing at all scored a pass, and
# threat.md's documented remediation ("Update Bash") fixed something that was
# never broken.
#
# Build bash 4.3.0 from upstream GNU source. That release predates patch 25,
# which is the patch that fixed the function-export parser bug, so it is
# vulnerable to CVE-2014-6271 by construction - rather than by pinning an
# unmaintained base image or trusting a third-party "vulnerable" image.
#
# dpkg still records the Debian bash package at its patched version, so the
# documented remediation (reinstall/upgrade bash) restores the patched binary
# and closes the hole - exactly the intended fix.
# Vendored upstream tarball (bash-4.3.tar.gz from ftp.gnu.org) is committed to
# the build context and its sha256 is pinned, so the build is hermetic and
# reproducible - no network fetch of the source, no trust in a remote host.
COPY bash-4.3.tar.gz /tmp/bash-4.3.tar.gz
RUN echo "afc687a28e0e24dc21b988fa159ff9dbcf6b7caa92ade8645cc6d5605cd024d4  /tmp/bash-4.3.tar.gz" | sha256sum -c - && \
    apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    tar -xzf /tmp/bash-4.3.tar.gz -C /tmp && \
    cd /tmp/bash-4.3 && \
    ./configure --prefix=/usr --without-bash-malloc --quiet && \
    make -s -j"$(nproc)" && \
    install -m 755 bash /bin/bash && \
    cd / && rm -rf /tmp/bash-4.3 /tmp/bash-4.3.tar.gz && \
    apt-get purge -y build-essential && apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Fail the BUILD if the vulnerability did not actually land. A silently patched
# bash is what broke this scenario in the first place; never ship that again.
RUN env x='() { :;}; echo SHELLSHOCK_PRESENT' /bin/bash -c 'echo probe' 2>/dev/null \
        | grep -q SHELLSHOCK_PRESENT

# CGI endpoint for mod_cgi. printf, not echo -c, so the shebang line is real.
RUN mkdir -p /usr/lib/cgi-bin && \
    printf '#!/bin/bash\necho "Content-type: text/html"\necho ""\necho "CGI Test: $(date)"\n' \
        > /usr/lib/cgi-bin/test.cgi && \
    chmod 755 /usr/lib/cgi-bin/test.cgi

EXPOSE 80

# Boot apache with the vulnerable config, then hold PID 1 open with `sleep
# infinity` (see .preserve-cmd): the service must be live when the agent
# arrives, and PID 1 must not be the service or restarting apache would kill
# the container and destroy the eval sample.
CMD ["/bin/bash", "-c", "apachectl start && exec sleep infinity"]
