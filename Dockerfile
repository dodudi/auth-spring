FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/logs && \
    chown -R appuser:appgroup /app/logs
USER appuser

COPY build/libs/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
