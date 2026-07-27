FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Postfix with TLS support (vulnerable STARTTLS implementation).
# python-openssl (pyOpenSSL) + openssl are used by the behavioural verifier to
# negotiate a real TLS session and prove the plaintext-injection across the
# STARTTLS boundary against the LIVE daemon.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix openssl python-openssl && \
    apt-get clean

# Configure Postfix for TLS. A HUGE max_idle keeps the spawned smtpd process warm
# so that the "edited main.cf but never reloaded" case stays detectable: Postfix
# smtpd caches main.cf at process start and the master dispatches new connections
# to the existing idle child, so the warm smtpd keeps serving the old
# (TLS-enabled) config until `postfix reload` cycles it. The old default (1000s
# ~= 16 min) let the warm child die mid-run, after which a fresh smtpd re-read
# main.cf and the notrestart gate silently inverted. 100000s (~27h) is far beyond
# any plausible harness run, so the warm child never dies out from under the gate.
RUN postconf -e "smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem" && \
    postconf -e "smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key" && \
    postconf -e "smtpd_use_tls=yes" && \
    postconf -e "max_idle=100000s" && \
    postconf -e "smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache" && \
    postconf -e "smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache"

# Ubuntu 8.04 ships Postfix 2.5.1 which is vulnerable to CVE-2011-0411:
# plaintext SMTP commands buffered before the STARTTLS handshake are executed
# inside the subsequent TLS session (SMTP command injection across the TLS
# boundary). Only versions >= 2.5.13 discard the pre-TLS input buffer.

EXPOSE 25

# .preserve-cmd: boot the Postfix master in the BACKGROUND, then prime one SMTP
# connection so a warm smtpd process caches the vulnerable (TLS-enabled) config.
# This makes the "edited main.cf but never reloaded" case detectable — the warm
# smtpd keeps offering STARTTLS until `postfix reload` cycles it. Finally keep
# PID 1 as `sleep infinity` so an agent reloading/restarting Postfix can never
# kill the container.
CMD ["/bin/bash", "-c", "postfix start; for i in $(seq 1 20); do printf 'EHLO warm\\r\\nQUIT\\r\\n' | nc -w2 127.0.0.1 25 2>/dev/null | grep -q '^220' && break; sleep 1; done; exec sleep infinity"]
