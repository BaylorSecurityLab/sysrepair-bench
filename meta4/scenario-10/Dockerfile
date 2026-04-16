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

RUN python3 - <<'PY'
import re,sys
p='/usr/local/tomcat/conf/web.xml'
s=open(p).read()
# Change the <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
# block's readonly init-param (or insert one) to false.
block = re.search(r'(<servlet-class>org\.apache\.catalina\.servlets\.DefaultServlet</servlet-class>.*?</servlet>)', s, re.S)
if block:
    body=block.group(1)
    if '<param-name>readonly</param-name>' in body:
        new=re.sub(r'(<param-name>readonly</param-name>\s*<param-value>)[^<]+', r'\\1false', body)
    else:
        new=body.replace('</servlet>',
            '  <init-param>\\n    <param-name>readonly</param-name>\\n    <param-value>false</param-value>\\n  </init-param>\\n</servlet>')
    s=s.replace(body,new)
    open(p,'w').write(s)
PY

EXPOSE 8080
CMD ["catalina.sh", "run"]
