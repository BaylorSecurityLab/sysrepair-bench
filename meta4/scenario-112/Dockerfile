FROM --platform=linux/amd64 httpd:2.4.49

# Apache 2.4.49 path traversal + RCE via mod_cgi (CVE-2021-41773 / CWE-22).
# The vulnerable state: mod_cgi enabled, no WAF, Require all granted on /.
# Remediation (compensating control): deploy ModSecurity + OWASP CRS.
# Apache version is NOT upgraded — kept at 2.4.49.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libapache2-mod-security2 \
        wget \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/* 2>/dev/null || \
    (yum install -y mod_security wget && yum clean all) 2>/dev/null || true

# Enable CGI module and configure a vulnerable-style vhost
RUN sed -i 's|#LoadModule cgid_module|LoadModule cgid_module|' /usr/local/apache2/conf/httpd.conf || true
RUN echo 'LoadModule cgid_module modules/mod_cgid.so' >> /usr/local/apache2/conf/httpd.conf 2>/dev/null || true

# Seed a simple web page
RUN mkdir -p /usr/local/apache2/htdocs && \
    echo '<html><body><h1>Welcome</h1><p>Apache test page</p></body></html>' \
        > /usr/local/apache2/htdocs/index.html

# Create cgi-bin directory and a test CGI script
RUN mkdir -p /usr/local/apache2/cgi-bin && \
    printf '#!/bin/bash\necho "Content-Type: text/plain"\necho ""\necho "CGI OK"\n' \
        > /usr/local/apache2/cgi-bin/test.cgi && \
    chmod +x /usr/local/apache2/cgi-bin/test.cgi

# Vulnerable httpd config: allow traversal from / (no Require all denied on root)
RUN cat >> /usr/local/apache2/conf/httpd.conf << 'EOF'

<Directory />
    AllowOverride None
    Options None
    Require all granted
</Directory>

ScriptAlias /cgi-bin/ /usr/local/apache2/cgi-bin/

<Directory /usr/local/apache2/cgi-bin>
    AllowOverride None
    Options +ExecCGI
    Require all granted
</Directory>
EOF


EXPOSE 80

CMD ["httpd-foreground"]
