FROM sysrepair/meta2-hardy:latest
# Install Apache HTTP Server. curl is needed by the behavioural verifier so it
# can issue a REAL request and read the Set-Cookie header the LIVE daemon emits.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 curl && \
    apt-get clean

# Use the default Apache 2.2 configuration, which has no Header directives to
# harden cookies. mod_usertrack then stamps a tracking cookie on every response
# with neither HttpOnly nor Secure.

# Enable mod_usertrack so the server really does set a cookie
RUN a2enmod usertrack 2>/dev/null || true

# Tracking cookie config without HttpOnly/Secure flags
RUN echo '<IfModule mod_usertrack.c>' > /etc/apache2/conf.d/tracking.conf && \
    echo '    CookieTracking on' >> /etc/apache2/conf.d/tracking.conf && \
    echo '    CookieName Apache_Track' >> /etc/apache2/conf.d/tracking.conf && \
    echo '</IfModule>' >> /etc/apache2/conf.d/tracking.conf

# No mod_headers configuration — cookies are sent without HttpOnly or Secure
# flags. This leaves the tracking cookie readable from JavaScript (XSS session
# theft) and lets it ride over plaintext HTTP.

# Create a simple test page
RUN echo '<html><body><h1>Apache Default Page</h1><p>Server is running.</p></body></html>' > /var/www/index.html

# Expose HTTP port
EXPOSE 80

# .preserve-cmd: boot Apache in the BACKGROUND so a real, vulnerable daemon is
# already stamping the flag-less Apache_Track cookie on responses when the agent
# starts (this makes the "wrote the Header directive but never restarted Apache"
# case detectable — mod_headers is only loaded at start-up), then keep PID 1 as
# `sleep infinity` so an agent restarting Apache can never kill the container.
CMD ["/bin/bash", "-c", ". /etc/apache2/envvars 2>/dev/null; apache2ctl start >/dev/null 2>&1; exec sleep infinity"]
