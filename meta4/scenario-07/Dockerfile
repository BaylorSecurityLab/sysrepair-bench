FROM --platform=linux/amd64 tomcat:9.0.98-jdk11-temurin

# Tomcat 9.0.0-9.0.98 — partial-PUT deserialization RCE (CVE-2025-24813).
# When the default servlet is writable (readonly=false) AND the app uses
# Tomcat's file-based HTTP session persistence (PersistentManager +
# FileStore), an attacker can upload a serialized Java object via partial
# PUT, then reference it with a matching JSESSIONID to trigger
# deserialization on session load — yielding RCE.

# Enable the writable default servlet (the vulnerable pre-condition).
RUN sed -i 's|<param-name>readonly</param-name>\s*<param-value>true</param-value>|<param-name>readonly</param-name><param-value>false</param-value>|' \
    /usr/local/tomcat/conf/web.xml && \
    grep -q 'readonly</param-name><param-value>false' /usr/local/tomcat/conf/web.xml || \
    sed -i 's|</servlet>|<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param></servlet>|' \
    /usr/local/tomcat/conf/web.xml

# Enable file-based session persistence (second precondition) on the ROOT context.
RUN mkdir -p /usr/local/tomcat/conf/Catalina/localhost
COPY ROOT.xml /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

EXPOSE 8080
CMD ["catalina.sh", "run"]
