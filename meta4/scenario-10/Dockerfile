FROM --platform=linux/amd64 tomcat:11.0.1-jdk21-temurin

# Tomcat 11.0.1 case-insensitive JSP upload race — CVE-2024-50379.
# Pre-conditions:
#   1. Default servlet `readonly=false`
#   2. Filesystem is case-insensitive on the directory holding the webapp
#   3. An attacker can PUT a JSP file, concurrently GET it
# On a case-insensitive FS the servlet check that would normally reject
# JSP-looking filenames can be bypassed via a TOCTOU race, leading to
# JSP execution.
#
# We flip `readonly=false` here; the case-insensitive requirement is a
# deployment concern on Windows/macOS/case-insensitive volumes.

# Insert readonly=false init-param into the DefaultServlet block using sed.
# If readonly is already present, flip it to false; otherwise insert a new block.
RUN if grep -q '<param-name>readonly</param-name>' /usr/local/tomcat/conf/web.xml; then \
        sed -i '/<param-name>readonly<\/param-name>/{ n; s|<param-value>[^<]*</param-value>|<param-value>false</param-value>|; }' \
            /usr/local/tomcat/conf/web.xml; \
    else \
        sed -i '/<servlet-class>org\.apache\.catalina\.servlets\.DefaultServlet<\/servlet-class>/a \
        <init-param>\n            <param-name>readonly</param-name>\n            <param-value>false</param-value>\n        </init-param>' \
            /usr/local/tomcat/conf/web.xml; \
    fi

EXPOSE 8080
CMD ["catalina.sh", "run"]
