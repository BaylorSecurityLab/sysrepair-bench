FROM --platform=linux/amd64 roundcube/roundcubemail:1.6.3-apache

# Roundcube 1.6.3 is vulnerable to stored XSS via SVG elements embedded in
# HTML emails (CVE-2023-5631). This version cannot be replaced by upgrade;
# compensating controls (CSP headers, SVG stripping) are required.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 80

CMD ["apache2-foreground"]
