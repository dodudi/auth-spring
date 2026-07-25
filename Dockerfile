FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /src
COPY . .
RUN chmod +x gradlew && ./gradlew clean build -x test --no-daemon

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/logs && \
    chown -R appuser:appgroup /app/logs
USER appuser
COPY --from=build /src/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]