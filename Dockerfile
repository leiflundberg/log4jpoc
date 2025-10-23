# Stage 1: Build with newer Maven (has Java 8u322)
FROM maven:3.8.4-jdk-8 AS builder

COPY . /usr/src/poc
WORKDIR /usr/src/poc
RUN mvn clean && mvn package

# Stage 2: Run with vulnerable Java 8u181 (JNDI RCE vulnerable)
FROM openjdk:8u181-jdk

COPY --from=builder /usr/src/poc/target/log4j-rce-1.0-SNAPSHOT-jar-with-dependencies.jar /app/app.jar
WORKDIR /app

# set this to disable the exploit
#ENV LOG4J_FORMAT_MSG_NO_LOOKUPS=true
ENV SECRET_VALUE='if you can read this this code is vulnerable'

# Java 8u181 is vulnerable to JNDI remote class loading (CVE-2017-10135, etc.)
# However, Debian backported security patches, so we need to explicitly enable remote class loading
# This flag enables JNDI remote class loading for demonstration purposes
# Also ensure message lookups are enabled (default in 2.14.1 but being explicit)
CMD ["java", "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", "-Dlog4j2.formatMsgNoLookups=false", "-cp", "/app/app.jar", "VulnerableApp"]
#CMD ["java", "-Dlog4j.formatMsgNoLookups=true", "-cp", "/app/app.jar", "VulnerableApp"]
