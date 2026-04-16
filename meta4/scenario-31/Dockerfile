FROM --platform=linux/amd64 wordpress:6.5-apache

# WordPress 6.5 + Really Simple Security (formerly Really Simple SSL)
# 9.0.0 — authentication bypass (CVE-2024-10924). When "Two-Factor
# Authentication" is enabled, the REST endpoint
# /wp-json/reallysimplesecurity/v1/two_fa/skip_onboarding accepted a
# `user_id` parameter without verifying the authenticated session,
# letting an unauthenticated attacker log in as any user, including
# administrator.

# Install the vulnerable plugin version via WP-CLI equivalents. We fetch
# the 9.0.0 zip from the WordPress plugin archive and drop it into the
# plugins directory.
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /usr/src/wordpress/wp-content/plugins && \
    curl -fsSLo /tmp/rss.zip \
        "https://downloads.wordpress.org/plugin/really-simple-ssl.9.0.0.zip" && \
    unzip -q /tmp/rss.zip -d /usr/src/wordpress/wp-content/plugins/ && \
    rm /tmp/rss.zip

EXPOSE 80
