FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Postfix with TLS support.
# Ubuntu 8.04 ships OpenSSL 0.9.8g, and Postfix's opportunistic-TLS default
# cipher grade ("export") accepts EXPORT-grade suites — FREAK (CVE-2015-0204)
# and LogJam (CVE-2015-4000). openssl s_client is used by the verifier to
# negotiate a real export cipher against the LIVE daemon.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix openssl && \
    apt-get clean

# Configure Postfix for TLS with the (vulnerable) default cipher grade. A HUGE
# max_idle keeps the spawned smtpd warm so the "edited main.cf but never
# reloaded" case stays detectable (smtpd caches main.cf at process start and the
# master reuses the idle child for new connections). The old default (1000s ~=
# 16 min) let the warm child die mid-run, after which a fresh smtpd re-read
# main.cf and the notrestart gate silently inverted. 100000s (~27h) is far
# beyond any plausible harness run.
RUN postconf -e "smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem" && \
    postconf -e "smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key" && \
    postconf -e "smtpd_use_tls=yes" && \
    postconf -e "max_idle=100000s" && \
    postconf -e "smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache" && \
    postconf -e "smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache"

# Old OpenSSL 0.9.8g accepts RSA_EXPORT (FREAK) and DHE_EXPORT (LogJam) cipher
# suites, and Postfix's default opportunistic cipher grade permits them.

EXPOSE 25

# .preserve-cmd: boot the Postfix master, prime one SMTP connection so a warm
# smtpd caches the vulnerable (export-permitting) config, then keep PID 1 as
# `sleep infinity` so an agent reloading Postfix cannot kill the container.
CMD ["/bin/bash", "-c", "postfix start; for i in $(seq 1 20); do printf 'EHLO warm\\r\\nQUIT\\r\\n' | nc -w2 127.0.0.1 25 2>/dev/null | grep -q '^220' && break; sleep 1; done; exec sleep infinity"]
