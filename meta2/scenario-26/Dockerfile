FROM sysrepair/meta2-hardy:latest
# Install Apache HTTP Server
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 && \
    apt-get clean

# Use default Apache 2.2 configuration which does NOT set HttpOnly or Secure
# flags on cookies. Apache 2.2 default error pages and mod_usertrack can
# set cookies without these protective flags.

# Enable mod_usertrack to demonstrate cookie-setting behavior
RUN a2enmod usertrack 2>/dev/null || true

# Add a tracking cookie config without HttpOnly/Secure flags
RUN echo '<IfModule mod_usertrack.c>' > /etc/apache2/conf.d/tracking.conf && \
    echo '    CookieTracking on' >> /etc/apache2/conf.d/tracking.conf && \
    echo '    CookieName Apache_Track' >> /etc/apache2/conf.d/tracking.conf && \
    echo '</IfModule>' >> /etc/apache2/conf.d/tracking.conf

# No mod_headers configuration — cookies are sent without HttpOnly or Secure flags
# This allows JavaScript access to cookies (XSS risk) and cookies sent over HTTP

# Create a simple test page
RUN echo '<html><body><h1>Apache Default Page</h1><p>Server is running.</p></body></html>' > /var/www/index.html

# Expose HTTP port
EXPOSE 80

# Start Apache in foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
