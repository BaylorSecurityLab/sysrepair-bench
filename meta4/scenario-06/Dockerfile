FROM --platform=linux/amd64 maven:3.8.6-openjdk-11 AS build

# Spring Cloud Function 3.2.2 SpEL injection — CVE-2022-22963.
# The routing function evaluates the spring.cloud.function.routing-expression
# HTTP header as a SpEL expression without sandboxing, yielding unauth RCE.
#
# This builds a real Spring Boot + Spring Cloud Function app exposing
# /functionRouter with two bean functions (uppercase, reverse). The
# routing-expression header is the exploit surface.

WORKDIR /src
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src src
RUN mvn package -DskipTests -B

# ---------- runtime ----------
FROM --platform=linux/amd64 eclipse-temurin:11-jre-jammy
COPY --from=build /src/target/scf-demo.jar /opt/app/app.jar

EXPOSE 8080
CMD ["java", "-jar", "/opt/app/app.jar"]
