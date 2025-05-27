# Dockerfile para auth-server
FROM eclipse-temurin:21-jre

ENV TZ=America/Caracas

WORKDIR /app

COPY target/auth-server-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 9000

ENTRYPOINT ["java", "-Duser.timezone=America/Caracas", "-jar", "app.jar"]
