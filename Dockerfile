cat > Dockerfile << 'EOF'
# 1단계: Gradle 빌드 (gradlew로 프로젝트 지정 버전 사용)
FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /src
COPY . .
RUN chmod +x gradlew && ./gradlew clean build -x test --no-daemon

# 2단계: 실행 이미지
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/logs && \
    chown -R appuser:appgroup /app/logs
USER appuser
COPY --from=build /src/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
EOF