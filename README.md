# auth-spring

Spring Boot 기반 OAuth2 인증 서버. Google 소셜 로그인을 지원하며, Authorization Code 흐름을 제공합니다.

## 목차
1. [분리된 Security Filter Chain로 이동](#분리된-security-filter-chain)  
2. [Spring Session + Redis 구현으로 인증 서버 세션 공유](#spring-session--redis-구현으로-인증-서버-세션-공유)  
3. [JWT + RSA 비대칭키](#JWT--RSA-비대칭키)  
4. [Admin 관리 페이지를 통한 Client 관리](#admin-관리-페이지를-통한-client-관리)  
5. [Prometheus + Grafana를 활용한 서비스 메트릭 모니터링](#prometheus--grafana를-활용한-서비스-메트릭-모니터링)  
6. [Loki + Promtail을 활용한 로그 수집 및 모니터링](#loki--promtail을-활용한-로그-수집-및-모니터링)  
---

## 분리된 Security Filter Chain
문제: 하나의 FilterChain 에서 모든 요청을 처리하여 코드가 복잡해지는 문제  
해결: FilterChain을 기능으로 분리하여 각자 처리해야할 요청 경로를 지정해서 처리하도록 구현

### Authorization Server 필터 체인 설정
- 해당 필터가 특정 경로의 요청을 처리할 수 있도록 securityMatcher 설정을 합니다.
- OIDC 설정으로 ID Token을 발급 받을 수 있도록 설정합니다.
- Access Token의 경우 권한 부여 정보를 담는 JWT 입니다. 주로 서버 API를 호출하기 위해 사용합니다.
- ID Token의 경우 사용자의 신원을 확인할 수 있는 정보를 담는 JWT 입니다. 주로 클라이언트에서 사용하기 위해 발급합니다.

```java
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    // .. 생략

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository) {
        http
                .oauth2AuthorizationServer(authorizationServer -> {
                    http.securityMatcher(authorizationServer.getEndpointsMatcher());
                    authorizationServer.oidc(Customizer.withDefaults());
                    authorizationServer.authorizationEndpoint(endpoint -> endpoint.errorResponseHandler(customAuthorizationServerFailureHandler));
                })
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new ClientAwareLoginUrlAuthenticationEntryPoint(registeredClientRepository),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    // ... 생략
}
```
#### 필터 체인 
<img width="667" height="277" alt="image" src="https://github.com/user-attachments/assets/fd479a8e-37ec-4877-ad3a-ff55593c2e87" />

### Admin 필터 체인 설정
- `/admin/**` 경로의 요청을 처리하도록 설정합니다.
- ROLE_ADMIN 권한으로 설정된 토큰으로 요청할 때 사용 가능하도록 권한 설정을 진행합니다.
- 로그인 페이지는 Security 기본 페이지가 아닌 Tymeleaf 로 구현한 커스텀 페이지를 사용하도록 구현합니다. (.loginPage)

```java
@Configuration
public class AdminSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher("/admin/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin/login").permitAll()
                        .anyRequest().hasRole("ADMIN")
                )
                .formLogin(form -> form
                        .loginPage("/admin/login")
                        .loginProcessingUrl("/admin/login")
                        .defaultSuccessUrl("/admin/clients", true)
                        .failureUrl("/admin/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/admin/logout")
                        .logoutSuccessUrl("/admin/login?logout=true")
                )
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

        return http.build();
    }

}
```
<img width="652" height="290" alt="image" src="https://github.com/user-attachments/assets/117fce93-503a-49a1-96b3-ba7a0f0e67ef" />

### Resource Server 필터 체인
```java
@Configuration
@EnableMethodSecurity
public class ResourceServerConfig {

    @Bean
    @Order(3)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
                .securityMatcher("/api/**")
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/v1/users/signup").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer((oauth2) -> oauth2
                        .jwt((jwt) -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                );

        return http.build();
    }

    // ... 생략
}
```
<img width="951" height="298" alt="image" src="https://github.com/user-attachments/assets/22db7561-58ef-4d9a-b0fe-1e64338625f3" />

### 나머지 처리 필터 체인
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${auth.allowed-origins}")
    private String allowedOrigins;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(4)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, SocialOAuth2UserService socialOAuth2UserService, ObjectMapper objectMapper) throws Exception {
        JsonAuthenticationSuccessHandler successHandler = new JsonAuthenticationSuccessHandler(objectMapper);
        JsonAuthenticationFailureHandler failureHandler = new JsonAuthenticationFailureHandler(objectMapper);

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/oauth/error").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(socialOAuth2UserService)
                        )
                );

        return http.build();
    }

    // ... 생략
}
```
<img width="794" height="318" alt="image" src="https://github.com/user-attachments/assets/085e3c2e-5af6-4024-9260-2310e328f248" />

## Spring Session + Redis 구현으로 인증 서버 세션 공유
문제: 하나의 인스턴스로 실행 중인 인증 서버에 장애가 발생할 경우 인증 서버를 사용하는 모든 서비스에 문제가 발생합니다.  
해결: 다중 인스턴스 간 세션 상태를 공유하여 동일한 세션 상태를 유지할 수 있도록 구현했습니다.
```java
@Configuration
@EnableRedisHttpSession(redisNamespace = "spring:session:auth", maxInactiveIntervalInSeconds = 3600)
public class SessionConfig implements BeanClassLoaderAware {

    private ClassLoader loader;

    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return new JacksonJsonRedisSerializer<>(createJsonMapper(), Object.class);
    }

    private static JsonMapper createJsonMapper() {
        BasicPolymorphicTypeValidator.Builder builder = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Object.class)
                .allowIfSubType("java.util.concurrent.")
                .allowIfSubType("java.util.")
                .allowIfSubType("org.springframework.security.")
                .allowIfSubType("org.springframework.session.");

        OAuth2AuthorizationServerJacksonModule authorizationServerJacksonModule = new OAuth2AuthorizationServerJacksonModule();
        authorizationServerJacksonModule.configurePolymorphicTypeValidator(builder);
        List<JacksonModule> securityJacksonModules = SecurityJacksonModules.getModules(JdbcOAuth2AuthorizationService.class.getClassLoader(), builder);
        return JsonMapper.builder()
                .addModules(authorizationServerJacksonModule)
                .addModules(securityJacksonModules)
                .build();
    }

    @Override
    public void setBeanClassLoader(@NonNull ClassLoader classLoader) {
        this.loader = classLoader;
    }
}
```

## JWT + RSA 비대칭키
문제: 인증 서버를 사용하기 위한 외부 서비스가 JWT 토큰 검증을 위한 비밀키를 설정해야 합니다. 이는 보안상 위험하다고 판단했습니다.
해결: RSA 비대칭키 방식을 사용하여 개인키를 인증 서버에 설정하고, 공개키는 개인키로 서명된 값을 검증하고, `/oauth2/jwks` 요청으로 공개키 확인을 하도록 구현했습니다.
```java
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final RsaProperty rsaProperty;

    // .. 생략

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = new RSAKey.Builder(rsaProperty.getPublicKey())
                .privateKey(rsaProperty.getPrivateKey())
                .keyID("auth-server-key")
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // .. 생략
}
```

## Admin 관리 페이지를 통한 Client 관리
문제: 서비스를 생성할 때마다 클라이언트 정보를 등록하고 관리해야 한다는 불편함이 존재합니다.
해결: 관리자 페이지를 통해서 `Client ID`, `Client Secret`, `Redirect URI`, `PKCE 여부`, `Grant Type`, `Token TTL` 등 다양한 정보를 쉽게 관리하도록 구현했습니다.  
- Client Secret 은 즉시 재발급 가능하도록 구현했으며, 기존 키는 무효화되어 해당 외부 서비스는 새롭게 발급된 키로 교체해야 합니다.
```java
@Configuration
public class AdminSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher("/admin/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin/login").permitAll()
                        .anyRequest().hasRole("ADMIN")
                )
                .formLogin(form -> form
                        .loginPage("/admin/login")
                        .loginProcessingUrl("/admin/login")
                        .defaultSuccessUrl("/admin/clients", true)
                        .failureUrl("/admin/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/admin/logout")
                        .logoutSuccessUrl("/admin/login?logout=true")
                )
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

        return http.build();
    }

}
```

## Prometheus + Grafana를 활용한 서비스 메트릭 모니터링
문제: 서비스 운영 중 발생하는 성능 이상이나 장애를 사전에 감지하기 어렵다는 문제가 있습니다.  
해결: Spring Actuator와 Micrometer를 연동해 핵심 메트릭을 Prometheus로 수집하고, Grafana 대시보드에서 실시간으로 시각화합니다.

### 의존성 설정
`micrometer-registry-prometheus`를 추가하면 `/actuator/prometheus` 엔드포인트가 활성화되어 Prometheus가 메트릭을 수집할 수 있습니다.

```gradle
// Observability
implementation 'org.springframework.boot:spring-boot-starter-actuator'

// Runtime
runtimeOnly 'io.micrometer:micrometer-registry-prometheus'
```

### Actuator 엔드포인트 노출 설정
`/actuator/prometheus` 엔드포인트만 외부에 노출하도록 설정합니다.

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health, info, prometheus
  endpoint:
    health:
      show-details: when-authorized
```

### Prometheus 수집 설정
Prometheus가 15초마다 `/actuator/prometheus`를 호출해 메트릭을 수집합니다.

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: auth-spring
    metrics_path: /actuator/prometheus
    static_configs:
      - targets:
          - host.docker.internal:30000
```

## Loki + Promtail을 활용한 로그 수집 및 모니터링
문제: 서버에 직접 접속하여 로그를 확인해야 하고, 어떤 지점에서 문제가 발생했는지 로그를 모두 찾아봐야 합니다.  
해결: Logback JSON Encoder로 구조화된 로그를 파일에 출력하고, Promtail(로그 수집 에이전트)이 이를 읽어 Loki(로그 저장소)로 전송합니다. Grafana에서 메트릭과 로그를 통합 조회할 수 있습니다.

### Logback 구조화 로그 설정
`prod` 프로파일에서는 `JsonEncoder`를 사용해 JSON 형태로 로그를 파일에 기록합니다. `RollingFileAppender`로 날짜별·크기별 로그 파일을 분리하고, 최대 30일치 3GB까지 보관합니다.

```xml
<appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>logs/auth-spring.log</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
        <fileNamePattern>logs/auth-spring.%d{yyyy-MM-dd}.%i.log.gz</fileNamePattern>
        <maxFileSize>100MB</maxFileSize>
        <maxHistory>30</maxHistory>
        <totalSizeCap>3GB</totalSizeCap>
    </rollingPolicy>
    <encoder class="ch.qos.logback.classic.encoder.JsonEncoder"/>
</appender>

<springProfile name="prod">
    <root level="INFO">
        <appender-ref ref="JSON_CONSOLE"/>
        <appender-ref ref="FILE"/>
    </root>
</springProfile>
```

### Promtail 수집 설정
Promtail이 로그 파일을 읽어 `level` 필드를 라벨로 추출한 뒤 Loki로 전송합니다. JSON 구조화 로그 덕분에 Grafana에서 `level`, `app` 등의 라벨로 필터링이 가능합니다.

```yaml
clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: auth-spring
    static_configs:
      - targets:
          - localhost
        labels:
          app: auth-spring
          env: prod
          __path__: /logs/auth-spring.log
    pipeline_stages:
      - json:
          expressions:
            level: level
      - labels:
          level:
```
