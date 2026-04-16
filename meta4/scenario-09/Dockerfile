FROM --platform=linux/amd64 httpd:2.4.50

# Apache httpd 2.4.50 — double-encoded traversal bypass (CVE-2021-42013).
# 2.4.50 patched 41773 but the check could be bypassed with double-encoded
# `.%%32%65/` sequences, re-enabling the same arbitrary-read and (with
# mod_cgi) RCE primitives.

RUN sed -i 's|#LoadModule cgi_module|LoadModule cgi_module|' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's|#LoadModule cgid_module|LoadModule cgid_module|' /usr/local/apache2/conf/httpd.conf && \
    cat >> /usr/local/apache2/conf/httpd.conf <<'EOF'

<Directory "/">
    AllowOverride None
    Require all granted
</Directory>
Alias /icons/ "/usr/local/apache2/icons/"
<Directory "/usr/local/apache2/icons">
    Options Indexes FollowSymLinks
    Require all granted
</Directory>
ScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"
<Directory "/usr/local/apache2/cgi-bin">
    Options +ExecCGI
    Require all granted
</Directory>
EOF
RUN mkdir -p /usr/local/apache2/cgi-bin

EXPOSE 80
CMD ["httpd-foreground"]
