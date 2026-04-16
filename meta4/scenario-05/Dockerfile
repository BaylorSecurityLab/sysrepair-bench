FROM --platform=linux/amd64 maven:3.8.6-openjdk-11 AS build

# Spring4Shell — CVE-2022-22965.
# Build a minimal Spring MVC WAR using Spring Framework 5.3.17 (via
# Spring Boot 2.6.6) for deployment on external Tomcat 9.0.60 + JDK 11.
# The data-binder in Spring ≤5.3.17 on JDK 9+ allows property-chain
# traversal through `class.module.classLoader.resources...` to overwrite
# Tomcat's AccessLogValve and drop a JSP webshell.

WORKDIR /src
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src src
RUN mvn package -DskipTests -B

# ---------- runtime ----------
FROM --platform=linux/amd64 tomcat:9.0.60-jdk11-openjdk

RUN rm -rf /usr/local/tomcat/webapps/ROOT \
           /usr/local/tomcat/webapps/docs \
           /usr/local/tomcat/webapps/examples \
           /usr/local/tomcat/webapps/host-manager \
           /usr/local/tomcat/webapps/manager

COPY --from=build /src/target/spring4shell-demo.war \
     /usr/local/tomcat/webapps/app.war

EXPOSE 8080
CMD ["catalina.sh", "run"]
