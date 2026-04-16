FROM --platform=linux/amd64 httpd:2.4.49

# Apache httpd 2.4.49 — path traversal + CGI RCE (CVE-2021-41773).
# The URL-normalization flaw lets `.%2e/` segments escape aliased
# directories. With mod_cgi enabled and /bin aliased, requests can both
# read /etc/passwd AND execute arbitrary commands via the CGI handler.

# Enable mod_cgi and alias a path outside the document root, recreating
# the "Require all granted" + aliased /cgi-bin/ configuration in which
# the CVE is reachable.
RUN sed -i 's|#LoadModule cgi_module|LoadModule cgi_module|' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's|#LoadModule cgid_module|LoadModule cgid_module|' /usr/local/apache2/conf/httpd.conf && \
    cat >> /usr/local/apache2/conf/httpd.conf <<'EOF'

Alias /icons/ "/usr/local/apache2/icons/"
<Directory "/usr/local/apache2/icons">
    Options Indexes FollowSymLinks
    Require all granted
</Directory>

<Directory "/">
    AllowOverride None
    Require all granted
</Directory>

ScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"
<Directory "/usr/local/apache2/cgi-bin">
    AllowOverride None
    Options +ExecCGI
    Require all granted
</Directory>
EOF

RUN mkdir -p /usr/local/apache2/cgi-bin

EXPOSE 80
CMD ["httpd-foreground"]
